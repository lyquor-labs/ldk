use super::{LyquidError, LyquidResult, NodeID, lyquor_api};
use lyquor_primitives::{
    Address, Bytes, CallParams, Certificate, Hash, InputABI, OracleSigner, PubKey, Signature, encode_object,
};
pub use lyquor_primitives::{OracleCert, OracleConfig, OracleHeader, OracleMessage, OracleResponse, OracleTarget};

pub struct Oracle {
    id: &'static str,
    threshold: usize,
    committee: super::network::HashMap<NodeID, PubKey>,
    config_hash: Hash,
    config_update: bool,
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
        }
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&mut self, id: NodeID) -> bool {
        let ret = self.committee.insert(id, ());
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

    /// Generate a certificate that testifies the validity of an oracle call to a target network
    /// (sequence backend).
    pub fn certify(
        &self, ctx: &impl super::internal::OracleCertifyContext, origin: Address, method: String, input: Bytes,
        target: OracleTarget,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 || self.committee.len() < self.threshold {
            return Err(crate::LyquidError::LyquidRuntime("Invalid oracle config.".into()))
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
            abi: InputABI::Lyquor,
        };
        let input = encode_object(&OracleMessage {
            header: OracleHeader {
                proposer: node,
                target,
                config_hash: self.config_hash.into(),
            },
            params: params.clone(),
        });
        let cert: Option<OracleCert> = lyquor_api::universal_procedural_call(
            lyquid,
            Some(format!("oracle::committee::{}", self.id)),
            "validate".into(),
            input,
            Some(self.committee()),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

        Ok(cert.map(move |c| {
            params.input = crate::encode_by_fields!(
                cert: OracleCert = c,
                input_raw: Bytes = params.input
            )
            .into();
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
    yea_sigs: Vec<(OracleSigner, Signature)>,
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
        if resp.verify(&self.msg_hash) {
            if self.voted.insert(node) {
                match resp.approval {
                    true => {
                        self.yea_sigs.push((
                            OracleSigner {
                                id: node,
                                key: oracle.committee.get(&node).unwrap().clone(),
                            },
                            resp.sig,
                        ));
                        self.yea += 1
                    }
                    false => self.nay += 1,
                }
            }
        }

        if self.result.is_none() {
            crate::println!("yea = {}, thres = {}", self.yea, oracle.threshold);
            if self.yea >= oracle.threshold {
                self.result = Some(Some(OracleCert {
                    header: self.msg_header,
                    new_config: if oracle.config_update {
                        Some(oracle.get_config())
                    } else {
                        None
                    },
                    cert: Certificate::new(self.yea_sigs.clone()),
                }))
            } else if oracle.committee.len() - self.nay < oracle.threshold {
                self.result = Some(None)
            }
        }
        self.result.clone()
    }
}
