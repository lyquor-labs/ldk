use super::*;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum OracleTarget {
    // Lyquor network fn
    LVM(LyquidID),
    // EVM-based sequence backend
    EVM(Address),
}

/// Contains all fields needed to define a call other than the call parameters.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct OracleHeader {
    /// Node that proposed the call for certification.
    pub proposer: NodeID,
    /// Destination of the call (where it will be finally executed).
    pub target: OracleTarget,
    // TODO: add target chain ID
    /// Oracle config digest.
    pub config_hash: HashBytes,
    /// Epoch number used by OracleDest.
    pub epoch: u32,
    /// Random nonce that uniquely identifies the certified call within an epoch.
    pub nonce: HashBytes,
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct OracleSigner {
    pub id: NodeID,
    pub key: PubKey,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleConfig {
    pub committee: Vec<OracleSigner>,
    pub threshold: usize,
}

impl OracleConfig {
    pub fn to_hash(&self) -> Hash {
        blake3::hash(&encode_object(self))
    }
}

#[derive(Serialize, Deserialize)]
pub struct OraclePreimage {
    pub header: OracleHeader,
    pub params: CallParams,
    pub approval: bool,
}

impl OraclePreimage {
    pub fn to_preimage(&self) -> Vec<u8> {
        encode_object(self)
    }

    pub fn to_hash(&self) -> Hash {
        blake3::hash(&self.to_preimage())
    }
}

/// Oracle certificate that could be sequenced.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleCert {
    pub header: OracleHeader,
    /// If Some, a new config is agreed upon for this and following certificates, and becomes
    /// effective until the next update.
    pub new_config: Option<OracleConfig>,
    /// Certifies a threshold approval for a digest (Certificate.digest).
    pub cert: Certificate,
}

impl OracleCert {
    pub fn verify<'a>(&'a self, msg: &[u8], mut config: &'a OracleConfig, config_hash: &Hash) -> bool {
        match &self.new_config {
            Some(new_config) => {
                let hash: HashBytes = new_config.to_hash().into();
                if hash != self.header.config_hash {
                    // Config mismatch.
                    return false;
                }
                config = new_config
            }
            None => {
                if &*self.header.config_hash != config_hash {
                    // Config mismatch.
                    return false;
                }
            }
        }

        self.cert.verify(msg, config)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Certificate {
    /// The index for each signer in the committee list of OracleConfig.
    pub signers: Vec<u16>,
    /// Vote signatures.
    pub signatures: Vec<Bytes>,
}

impl Certificate {
    /// Map signers to committee indices to form bitmap, and serialize signatures.
    pub fn new(sigs: Vec<(OracleSigner, Signature)>, config: &OracleConfig) -> Self {
        // Build a look up table to find the signer's index.
        let mut index_of = std::collections::HashMap::new();
        for (i, s) in config.committee.iter().enumerate() {
            index_of.insert(s.id, i);
        }
        let mut signers: Vec<u16> = Vec::new();
        let mut signatures = Vec::new();
        for (signer, sig) in sigs.into_iter() {
            if let Some(i) = index_of.get(&signer.id).copied() {
                signers.push(i as u16);
                signatures.push(sig);
            }
        }
        Self { signers, signatures }
    }

    pub fn verify(&self, msg: &[u8], config: &OracleConfig) -> bool {
        if self.signers.len() != self.signatures.len() {
            // Malformed certificate.
            return false;
        }

        if self.signers.len() < config.threshold {
            // Threshold not met.
            return false
        }

        for (idx, sig) in self.signers.iter().zip(self.signatures.iter().take(config.threshold)) {
            let idx = (*idx) as usize;
            let signer = if idx < config.committee.len() {
                &config.committee[idx]
            } else {
                // Invalid signer index.
                return false
            };
            let sig = match ed25519_compact::Signature::from_slice(sig) {
                Ok(s) => s,
                Err(_) => return false,
            };
            if signer.key.0.verify(msg, &sig).is_err() {
                return false;
            }
        }
        true
    }
}

pub mod eth {
    use alloy_sol_types::{SolType, sol};
    sol! {
        struct OracleHeader {
            bytes32 proposer;
            address target;
            bytes32 configHash;
            uint32 epoch;
            bytes32 nonce;
        }

        struct OracleConfig {
            address[] committee;
            uint16 threshold;
        }

        struct OraclePreimage {
            OracleHeader header;
            string method; // Invoked method of the contract.
            bytes input; // Raw input for the call.
            bool approval; // Should always be true signed by multi-sigs that make up the final cert.
        }
    }

    impl OracleConfig {
        pub fn to_hash(&self) -> super::Hash {
            alloy_primitives::keccak256(&OracleConfig::abi_encode(self)).0.into()
        }
    }

    impl OraclePreimage {
        pub fn to_preimage(&self) -> Vec<u8> {
            Self::abi_encode(self)
        }

        pub fn to_hash(&self) -> super::Hash {
            alloy_primitives::keccak256(&self.to_preimage()).0.into()
        }
    }

    impl TryFrom<super::OracleHeader> for OracleHeader {
        type Error = ();

        fn try_from(oh: super::OracleHeader) -> Result<Self, ()> {
            Ok(OracleHeader {
                proposer: <[u8; 32]>::from(oh.proposer).into(),
                target: match oh.target {
                    super::OracleTarget::LVM(_) => return Err(()),
                    super::OracleTarget::EVM(t) => t,
                },
                configHash: <[u8; 32]>::from(oh.config_hash).into(),
                epoch: oh.epoch,
                nonce: <[u8; 32]>::from(oh.nonce).into(),
            })
        }
    }

    impl From<OracleHeader> for super::OracleHeader {
        fn from(oh: OracleHeader) -> Self {
            Self {
                proposer: <[u8; 32]>::from(oh.proposer).into(),
                target: super::OracleTarget::EVM(oh.target),
                config_hash: <[u8; 32]>::from(oh.configHash).into(),
                epoch: oh.epoch,
                nonce: <[u8; 32]>::from(oh.nonce).into(),
            }
        }
    }

    impl TryFrom<super::OraclePreimage> for OraclePreimage {
        type Error = ();
        fn try_from(om: super::OraclePreimage) -> Result<Self, ()> {
            Ok(Self {
                header: om.header.try_into()?,
                method: om.params.method,
                input: om.params.input.into(),
                approval: om.approval,
            })
        }
    }
}
