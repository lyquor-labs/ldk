use super::network::HashMap;
use super::{LyquidResult, NodeID};
use lyquor_primitives::{Hash, OracleCall, OracleCert, OracleConfig, OracleSigner, PubKey, encode_object};

pub struct Oracle {
    threshold: usize,
    committee: HashMap<NodeID, PubKey>,
    cached: (OracleConfig, Hash),
}

impl Oracle {
    fn updated_cached(&mut self) {
        let config = OracleConfig {
            committee: self
                .committee
                .iter()
                .map(|(id, key)| OracleSigner { id: *id, key: *key })
                .collect(),
            threshold: self.threshold,
        };
        let hash = lyquor_primitives::blake3::hash(&encode_object(&config));
        self.cached = (config, hash);
    }

    pub fn new() -> Self {
        Self {
            threshold: 0,
            committee: super::network::new_hashmap(),
            cached: (
                OracleConfig {
                    threshold: 0,
                    committee: Vec::new(),
                },
                [0; 32].into(),
            ),
        }
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&mut self, id: NodeID) -> bool {
        let ret = self.committee.insert(id, ());
        self.updated_cached();
        ret.is_none()
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node(&mut self, node: &NodeID) -> bool {
        let ret = self.committee.remove(node);
        self.updated_cached();
        ret.is_some()
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold(&mut self, new_thres: usize) {
        self.threshold = new_thres;
        self.updated_cached();
    }

    /// Generate a certificate that testifies the validity of an oracle call to a target network
    /// (sequence backend).
    pub fn certify(
        &self, ctx: &impl super::internal::OracleCertifyContext, call: OracleCall, full_config: bool,
    ) -> LyquidResult<OracleCert> {
        if self.threshold == 0 || self.committee.len() < self.threshold {
            return Err(crate::LyquidError::LyquidRuntime("Invalid oracle config.".into()))
        }
        let _ = ctx;
        let (_, _me) = super::lyquor_api::whoami()?;
        // TODO make a upc call here and wait for responses.
        Ok(OracleCert {
            config_hash: self.cached.1,
            config: if full_config { Some(self.cached.0.clone()) } else { None },
            cert: (),
        })
    }
}
