use super::{LyquidError, LyquidResult, NodeID, lyquor_api};
use lyquor_primitives::{
    Address, Bytes, CallParams, Certificate, Hash, InputABI, OracleSigner, PubKey, Signature, encode_object,
};
pub use lyquor_primitives::{OracleCert, OracleConfig, OracleHeader, OracleMessage, OracleResponse, OracleTarget};

/// Maximum number of unique nonces allowed per epoch on LVM before auto-advancing the epoch.
const NONCE_LIMIT_PER_EPOCH: usize = 1_000_000;

pub struct Oracle {
    id: &'static str,
    threshold: usize,
    committee: super::network::HashMap<NodeID, PubKey>,
    config_hash: Hash,
    config_update: bool,
    epoch: u32,
    // Per-epoch nonce deduplication set for the current epoch.
    nonce_seen: super::network::HashMap<[u8; 32], ()>,
}

impl Oracle {
    fn updated_config(&mut self) {
        let hash = lyquor_primitives::blake3::hash(&encode_object(&self.get_config()));
        self.config_hash = hash;
        self.config_update = true;
    }

    fn get_config(&self) -> OracleConfig {
        let mut committee = Vec::new();
        for (id, key) in self.committee.iter() {
            committee.push(OracleSigner { id: *id, key: *key });
        }
        OracleConfig {
            committee,
            threshold: self.threshold,
        }
    }

    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            threshold: 0,
            committee: super::network::new_hashmap(),
            config_hash: [0; 32].into(),
            config_update: false,
            epoch: 0,
            nonce_seen: super::network::new_hashmap(),
        }
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&mut self, id: NodeID) -> bool {
        let pk = id.as_ed25519_public_key();
        let ret = self.committee.insert(id, pk.into());
        self.updated_config();
        ret.is_none()
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node(&mut self, id: &NodeID) -> bool {
        let ret = self.committee.remove(id);
        self.updated_config();
        ret.is_some()
    }

    /// Get the committee size.
    pub fn len(&self) -> usize {
        self.committee.len()
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold(&mut self, new_thres: usize) {
        self.threshold = new_thres;
        self.updated_config();
    }

    /// Get the current epoch (used for hybrid replay prevention).
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Advance epoch to a strictly higher value. Returns true if advanced.
    pub fn advance_epoch(&mut self, new_epoch: u32) -> bool {
        if new_epoch > self.epoch {
            self.epoch = new_epoch;
            // Reset dedup set on epoch advance
            self.nonce_seen = super::network::new_hashmap();
            true
        } else {
            false
        }
    }

    /// Record a nonce for the given epoch. Returns false if stale epoch or nonce already seen.
    pub fn record_nonce(&mut self, epoch: u32, nonce: [u8; 32]) -> bool {
        if epoch < self.epoch {
            return false;
        }
        if epoch > self.epoch {
            self.epoch = epoch;
            self.nonce_seen = super::network::new_hashmap();
        }
        if self.nonce_seen.insert(nonce, ()).is_some() {
            return false; // duplicate
        }
        if self.nonce_seen.len() >= NONCE_LIMIT_PER_EPOCH {
            // Auto-advance epoch and reset dedup set for next epoch
            self.epoch = self.epoch.saturating_add(1);
            self.nonce_seen = super::network::new_hashmap();
        }
        true
    }

    /// Generate a certificate that testifies the validity of an oracle call to a target network
    /// (sequence backend).
    pub fn certify(
        &self, ctx: &impl super::internal::OracleCertifyContext, origin: Address, method: String, input: Bytes,
        target: OracleTarget,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 || self.committee.len() < self.threshold {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "Invalid oracle config. threshold={}, committee_len={}",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }
        let _ = ctx;
        let (node, lyquid) = super::lyquor_api::whoami()?;
        // The network fn call to be certified.
        let mut params = CallParams {
            origin,
            caller: origin, // TODO: use node/lyquid here?
            group: self.id.into(),
            method,
            input,
            abi: match target {
                OracleTarget::SequenceVM(_) => InputABI::Eth,
                _ => InputABI::Lyquor,
            },
        };
        // Populate epoch from network state and derive a nonce per call.
        // The nonce is derived from the call parameters to ensure uniqueness without RNG.
        let epoch: u32 = self.epoch;
        let nonce_hash = lyquor_primitives::blake3::hash(&encode_object(&params));
        let nonce: [u8; 32] = *nonce_hash.as_bytes();
        let header = OracleHeader {
            proposer: node,
            target,
            config_hash: self.config_hash.into(),
            epoch,
            nonce,
        };
        let message = OracleMessage {
            header,
            params: params.clone(),
        };
        let msg_hash: Hash = lyquor_primitives::blake3::hash(&encode_object(&message));
        let input = lyquor_primitives::encode_by_fields!(msg: OracleMessage = message);
        let cert: Option<OracleCert> = lyquor_api::universal_procedural_call(
            lyquid,
            Some(format!("oracle::committee::{}", self.id)),
            "validate".into(),
            input,
            Some(
                lyquor_primitives::encode_by_fields!(
                    // Use Oracle macro expected field "callee" for callee list and pass verification context.
                    callee: Vec<NodeID> = self.committee(),
                    header: OracleHeader = header,
                    msg_hash: lyquor_primitives::HashBytes = msg_hash.into()
                )
                .into(),
            ),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

        Ok(cert.map(move |cert| {
            params.input = crate::encode_by_fields!(cert: OracleCert = cert, input_raw: Bytes = params.input).into();
            params
        }))
    }

    pub fn committee(&self) -> Vec<NodeID> {
        self.committee.keys().cloned().collect()
    }

    pub fn config_hash(&self) -> &Hash {
        &self.config_hash
    }
}

pub struct Aggregation {
    msg_header: OracleHeader,
    msg_hash: Hash,

    voted: super::volatile::HashSet<NodeID>,
    yea_sigs: Vec<(OracleSigner, Signature, Option<Bytes>)>,
    yea: usize,
    nay: usize,

    result: Option<Option<OracleCert>>,
}

impl Aggregation {
    pub fn new(msg_header: OracleHeader, msg_hash: Hash) -> Self {
        Self {
            msg_header,
            msg_hash,
            voted: super::volatile::new_hashset(),
            yea_sigs: Vec::new(),
            yea: 0,
            nay: 0,
            result: None,
        }
    }

    pub fn add_response(&mut self, node: NodeID, resp: OracleResponse, oracle: &Oracle) -> Option<Option<OracleCert>> {
        // Delegate signature verification to the host-side API. If verification fails or the
        // host API errors, treat this as a failed vote.
        let ok = super::lyquor_api::oracle_verify(self.msg_hash.into(), resp.approval, resp.sig.ed25519.clone(), node)
            .unwrap_or(false);

        if ok && self.voted.insert(node) {
            match resp.approval {
                true => {
                    let evm_sig: Option<Bytes> = resp.sig.evm.clone();
                    self.yea_sigs.push((
                        OracleSigner {
                            id: node,
                            key: *oracle.committee.get(&node).unwrap(),
                        },
                        resp.sig.ed25519,
                        evm_sig,
                    ));
                    self.yea += 1
                }
                false => self.nay += 1,
            }
        }

        if self.result.is_none() {
            crate::println!("yea = {}, thres = {}", self.yea, oracle.threshold);
            if self.yea >= oracle.threshold {
                let cfg = oracle.get_config();
                self.result = Some(Some(OracleCert {
                    header: self.msg_header,
                    new_config: if oracle.config_update { Some(cfg.clone()) } else { None },
                    cert: Certificate::new(self.msg_hash.into(), self.yea_sigs.clone(), &cfg),
                }))
            } else if oracle.committee.len() - self.nay < oracle.threshold {
                self.result = Some(None)
            }
        }
        self.result.clone()
    }
}
