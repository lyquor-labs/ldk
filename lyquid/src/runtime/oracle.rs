use super::{LyquidError, LyquidResult, NodeID, lyquor_api};
use lyquor_primitives::{
    Address, Bytes, CallParams, Certificate, Hash, InputABI, OracleSigner, PubKey, Signature, encode_object,
};
pub use lyquor_primitives::{OracleCert, OracleConfig, OracleHeader, OracleMessage, OracleResponse, OracleTarget};

/// FIXME: eliminate this function.
/// Construct the canonical EVM-side OracleMessage with keccak256 digest that ECDSA signers are expected to sign.
pub fn evm_digest(header: &OracleHeader, params: &CallParams) -> super::Hash {
    use lyquor_primitives::alloy_primitives::keccak256;

    let (target_type, target_addr): (u8, Address) = match header.target {
        OracleTarget::Lyquor(_) => (0, Address::ZERO),
        OracleTarget::SequenceVM(addr) => (1, addr),
    };

    let cfg = keccak256(header.config_hash.as_bytes());
    let input = keccak256(params.input.as_ref());
    let selector = keccak256(params.method.as_bytes());

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"lyquor-cert-v1");
    preimage.extend_from_slice(cfg.as_slice());
    preimage.extend_from_slice(&header.epoch.to_be_bytes());
    preimage.extend_from_slice(header.nonce.as_bytes());
    preimage.push(target_type);
    preimage.extend_from_slice(target_addr.as_slice());
    preimage.extend_from_slice(&selector.as_slice()[..4]);
    preimage.extend_from_slice(input.as_slice());

    let d = keccak256(preimage);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(d.as_slice());
    bytes.into()
}

pub struct Oracle {
    id: &'static str,
    threshold: usize,
    committee: super::network::HashMap<NodeID, PubKey>,
    config_hash: Hash,
    config_update: bool,
}

impl Oracle {
    fn updated_config(&mut self) {
        let hash = lyquor_primitives::blake3::hash(&encode_object(&self.consolidate_config()));
        self.config_hash = hash;
        self.config_update = true;
    }

    fn consolidate_config(&self) -> OracleConfig {
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
        }
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&mut self, id: NodeID) -> bool {
        let pk = id.as_ed25519_public_key();
        if self.committee.insert(id, pk.into()).is_some() {
            return false;
        }
        self.updated_config();
        true
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node(&mut self, id: &NodeID) -> bool {
        if self.committee.remove(id).is_none() {
            return false;
        }
        self.updated_config();
        true
    }

    /// Get the committee size.
    pub fn len(&self) -> usize {
        self.committee.len()
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold(&mut self, new_thres: usize) -> bool {
        if new_thres == self.threshold {
            return true;
        }
        self.threshold = new_thres;
        self.updated_config();
        true
    }

    /// Generate a certificate that testifies the validity of an oracle call to a target network
    /// (sequence backend).
    pub fn certify(
        &self, ctx: &impl super::internal::OracleCertifyContext, origin: Address, method: String, input: Bytes,
        target: OracleTarget,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 || self.committee.len() < self.threshold || self.committee.len() > u16::MAX as usize {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "Invalid oracle config: threshold={}, committee.len()={}.",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }

        let node = ctx.get_node_id();
        let lyquid = ctx.get_lyquid_id();

        // The network fn call to be certified.
        let mut params = CallParams {
            origin,
            caller: origin, // TODO: use node/lyquid here?
            group: self.id.into(),
            method,
            input,
            abi: match target {
                OracleTarget::SequenceVM(_) => InputABI::Eth,
                OracleTarget::Lyquor(_) => InputABI::Lyquor,
            },
        };

        // Populate epoch from instance state and derive a nonce per call.
        let nonce = Hash::from_slice(&lyquor_api::random_bytes(32)?)
            .map_err(|_| LyquidError::LyquidRuntime("Oracle: invalid random nonce from the host.".into()))?
            .into();
        let epoch: u32 = 0; // FIXME: use the cached epoch from instance state.
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
        let msg_hash: Hash = match target {
            OracleTarget::SequenceVM(_) => evm_digest(&message.header, &message.params),
            OracleTarget::Lyquor(_) => lyquor_primitives::blake3::hash(&encode_object(&message)),
        };
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
        let msg: Bytes = lyquor_primitives::Bytes::copy_from_slice(&lyquor_primitives::lvm_digest(
            &self.msg_hash.into(),
            resp.approval,
        ));
        let ok = super::lyquor_api::verify(msg, resp.ed25519_sig.clone(), node).unwrap_or(false);

        if ok && self.voted.insert(node) {
            match resp.approval {
                true => {
                    self.yea_sigs.push((
                        OracleSigner {
                            id: node,
                            key: *oracle.committee.get(&node).unwrap(),
                        },
                        resp.ed25519_sig.clone(),
                        resp.ecdsa_sig.clone(),
                    ));
                    self.yea += 1
                }
                false => self.nay += 1,
            }
        }

        if self.result.is_none() {
            crate::println!("yea = {}, thres = {}", self.yea, oracle.threshold);
            if self.yea >= oracle.threshold {
                let cfg = oracle.consolidate_config();
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
