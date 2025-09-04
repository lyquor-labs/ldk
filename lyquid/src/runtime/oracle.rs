use super::{LyquidError, LyquidResult, NodeID, lyquor_api};
use lyquor_primitives::{
    Address, Bytes, CallParams, Certificate, EventABI, Hash, OracleConfig, OracleSigner, PubKey, Signature,
    encode_object,
};
pub use lyquor_primitives::{OracleCert, OracleHeader, OracleMessage, OracleResponse, OracleTarget};
use std::collections::HashSet;

pub struct Oracle {
    id: &'static str,
    threshold: usize,
    committee: super::network::HashMap<NodeID, PubKey>,
    config_cached: (OracleConfig, Hash),
    config_update: bool,
}

impl Oracle {
    fn updated_config(&mut self) {
        let config = OracleConfig {
            committee: self
                .committee
                .iter()
                .map(|(id, key)| OracleSigner { id: *id, key: *key })
                .collect(),
            threshold: self.threshold,
        };
        let hash = lyquor_primitives::blake3::hash(&encode_object(&config));
        self.config_cached = (config, hash);
        self.config_update = true;
    }

    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            threshold: 0,
            committee: super::network::new_hashmap(),
            config_cached: (
                OracleConfig {
                    threshold: 0,
                    committee: Vec::new(),
                },
                [0; 32].into(),
            ),
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
    pub fn remove_node(&mut self, node: &NodeID) -> bool {
        let ret = self.committee.remove(node);
        self.updated_config();
        ret.is_some()
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
    ) -> LyquidResult<Option<CallParams<Bytes>>> {
        if self.threshold == 0 || self.committee.len() < self.threshold {
            return Err(crate::LyquidError::LyquidRuntime("Invalid oracle config.".into()))
        }
        let _ = ctx;
        let (node, lyquid) = super::lyquor_api::whoami()?;
        // The network fn call to be certified.
        let mut params = CallParams {
            origin,
            caller: origin, // TODO: use node/lyquid here?
            group: format!("oracle::certified::{}", self.id),
            method,
            input,
            input_cert: None,
            abi: EventABI::Lyquor,
        };
        let input = encode_object(&OracleMessage {
            header: OracleHeader {
                proposer: node,
                target,
                config_hash: self.config_cached.1.into(),
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
            params.input_cert = Some(std::sync::Arc::new(c));
            params
        }))
    }

    pub fn committee(&self) -> Vec<NodeID> {
        self.committee.keys().cloned().collect()
    }

    pub fn config_hash(&self) -> &Hash {
        &self.config_cached.1
    }
}

pub struct Aggregation {
    msg_header: OracleHeader,
    msg_hash: Hash,

    voted: HashSet<NodeID>,
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
            voted: HashSet::new(),
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
            if self.yea >= oracle.threshold {
                self.result = Some(Some(OracleCert {
                    header: self.msg_header,
                    new_config: if oracle.config_update {
                        Some(oracle.config_cached.0.clone())
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
