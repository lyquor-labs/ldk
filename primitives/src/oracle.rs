use super::*;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum OracleTarget {
    // Lyquor network fn
    LVM(LyquidID),
    // EVM-based sequence backend
    EVM(Address),
}

impl OracleTarget {
    pub fn cipher(&self) -> Cipher {
        match self {
            Self::EVM(_) => Cipher::Secp256k1,
            Self::LVM(_) => Cipher::Ed25519,
        }
    }
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

pub type SignerID = u32;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleSigner {
    pub id: SignerID,
    pub key: Bytes,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleConfig {
    pub committee: Vec<OracleSigner>,
    pub threshold: u16,
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

#[derive(Serialize, Deserialize)]
pub struct ProposePreimage {
    pub header: OracleHeader,
    pub args: Bytes,
    pub value: Bytes,
}

impl ProposePreimage {
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
    /// Signers for the signatures in order.
    pub signers: Vec<SignerID>,
    /// Vote signatures.
    pub signatures: Vec<Bytes>,
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

        struct OracleSigner {
            uint32 id;
            address key;
        }

        struct OracleConfig {
            OracleSigner[] committee;
            uint16 threshold;
        }

        struct OraclePreimage {
            OracleHeader header;
            string method; // Invoked method of the contract.
            bytes input; // Raw input for the call.
            bool approval; // Should always be true signed by multi-sigs that make up the final cert.
        }

        struct ProposePreimage {
            OracleHeader header;
            bytes args;
            bytes value;
        }
    }

    impl OracleConfig {
        pub fn to_hash(&self) -> super::Hash {
            alloy_primitives::keccak256(&OracleConfig::abi_encode(self)).0.into()
        }
    }

    impl Default for OracleConfig {
        fn default() -> Self {
            Self {
                committee: Default::default(),
                threshold: Default::default(),
            }
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

    impl ProposePreimage {
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

    impl From<super::OracleConfig> for OracleConfig {
        fn from(oc: super::OracleConfig) -> Self {
            Self {
                committee: oc
                    .committee
                    .into_iter()
                    .map(|s| OracleSigner {
                        id: s.id,
                        key: s.key.as_ref().try_into().unwrap(),
                    })
                    .collect(),
                threshold: oc.threshold as u16,
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

    impl TryFrom<super::ProposePreimage> for ProposePreimage {
        type Error = ();
        fn try_from(pm: super::ProposePreimage) -> Result<Self, ()> {
            Ok(Self {
                header: pm.header.try_into()?,
                args: pm.args.into(),
                value: pm.value.into(),
            })
        }
    }
}
