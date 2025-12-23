use super::{LyquidError, LyquidResult, NodeID, lyquor_api};
use lyquor_primitives::{Address, Bytes, CallParams, Certificate, Hash, HashBytes, InputABI, OracleSigner, Signature};
pub use lyquor_primitives::{
    OracleCert, OracleConfig, OracleHeader, OracleMessage, OraclePreimage, OracleResponse, OracleTarget, eth,
};

pub struct Digest {
    pub lvm: Hash,
    pub evm: Hash,
}

impl Digest {
    const ZERO: Digest = Digest {
        lvm: Hash::from_bytes([0; 32]),
        evm: Hash::from_bytes([0; 32]),
    };
}

pub struct Oracle {
    id: &'static str,
    threshold: usize,
    committee: super::network::HashMap<NodeID, OracleSigner>,
    config_hash: Digest,
    config_update: bool,
}

impl Oracle {
    fn updated_config(&mut self) {
        let config = self.consolidate_config();
        self.config_hash = Digest {
            lvm: config.to_hash(),
            evm: lyquor_primitives::eth::OracleConfig {
                committee: config
                    .committee
                    .into_iter()
                    .map(|s| lyquor_api::eth_address_by_node(s.id).unwrap())
                    .collect(),
                threshold: config.threshold as u16,
            }
            .to_hash(),
        };
        self.config_update = true;
    }

    fn consolidate_config(&self) -> OracleConfig {
        let committee: Vec<OracleSigner> = self.committee.values().cloned().collect();
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
            config_hash: Digest::ZERO,
            config_update: false,
        }
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&mut self, id: NodeID) -> bool {
        let key = id.as_ed25519_public_key().into();
        let signer = OracleSigner { id, key };
        if self.committee.insert(id, signer).is_some() {
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
        let (abi, config_hash) = match target {
            OracleTarget::EVM(_) => (InputABI::Eth, self.config_hash.evm),
            OracleTarget::LVM(_) => (InputABI::Lyquor, self.config_hash.lvm),
        };
        let mut params = CallParams {
            origin,
            caller: origin, // TODO: use node/lyquid here?
            group: self.id.into(),
            method,
            input,
            abi,
        };

        // Populate epoch from instance state and derive a nonce per call.
        let nonce = Hash::from_slice(&lyquor_api::random_bytes(32)?)
            .map_err(|_| LyquidError::LyquidRuntime("Oracle: invalid random nonce from the host.".into()))?
            .into();
        let epoch: u32 = 0; // FIXME: use the cached epoch from instance state.
        let header = OracleHeader {
            proposer: node,
            target,
            config_hash: config_hash.into(),
            epoch,
            nonce,
        };

        let yay_preimage = OraclePreimage {
            header,
            params: params.clone(),
            approval: true,
        };

        let nay_preimage = OraclePreimage {
            header,
            params: params.clone(),
            approval: false,
        };

        // Seal the yay/nay hash for the signature.
        let (yay_hash, nay_hash) = match target {
            OracleTarget::EVM(_) => (
                lyquor_primitives::eth::OraclePreimage::try_from(yay_preimage)
                    .unwrap()
                    .to_hash(),
                lyquor_primitives::eth::OraclePreimage::try_from(nay_preimage)
                    .unwrap()
                    .to_hash(),
            ),
            OracleTarget::LVM(_) => (yay_preimage.to_hash(), nay_preimage.to_hash()),
        };

        let cert: Option<OracleCert> = lyquor_api::universal_procedural_call(
            lyquid,
            Some(format!("oracle::committee::{}", self.id)),
            "validate".into(),
            lyquor_primitives::encode_by_fields!(msg: OracleMessage = OracleMessage {
                header,
                params: params.clone(),
            }),
            Some(
                lyquor_primitives::encode_by_fields!(
                    // Use Oracle macro expected field "callee" for callee list and pass verification context.
                    callee: Vec<NodeID> = self.committee(),
                    header: OracleHeader = header,
                    yay_hash: HashBytes = yay_hash.into(),
                    nay_hash: HashBytes = nay_hash.into()
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

    pub fn config_hash(&self) -> &Digest {
        &self.config_hash
    }
}

pub struct Aggregation {
    header: OracleHeader,
    yea_hash: Hash,
    nay_hash: Hash,

    voted: super::volatile::HashSet<NodeID>,
    yea_sigs: Vec<(OracleSigner, Signature)>,
    yea: usize,
    nay: usize,

    result: Option<Option<OracleCert>>,
}

impl Aggregation {
    pub fn new(header: OracleHeader, yea_hash: Hash, nay_hash: Hash) -> Self {
        Self {
            header,
            yea_hash,
            nay_hash,
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
        let ok = super::lyquor_api::verify(
            match resp.approval {
                true => self.yea_hash,
                false => self.nay_hash,
            }
            .as_bytes()
            .to_vec()
            .into(),
            resp.sig.clone(),
            match self.header.target {
                OracleTarget::EVM(_) => lyquor_primitives::Cipher::EcdsaSecp256k1,
                OracleTarget::LVM(_) => lyquor_primitives::Cipher::Ed25519,
            },
            node,
        )
        .unwrap_or(false);
        if ok && self.voted.insert(node) {
            match resp.approval {
                true => {
                    self.yea_sigs
                        .push((*oracle.committee.get(&node).unwrap(), resp.sig.clone()));
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
                    header: self.header,
                    new_config: if oracle.config_update { Some(cfg.clone()) } else { None },
                    cert: Certificate::new(self.yea_hash.into(), self.yea_sigs.clone(), &cfg),
                }))
            } else if oracle.committee.len() - self.nay < oracle.threshold {
                self.result = Some(None)
            }
        }
        self.result.clone()
    }
}
