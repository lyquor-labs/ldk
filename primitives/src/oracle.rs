use super::*;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum OracleServiceTarget {
    // Lyquor network fn
    LVM(LyquidID),
    // EVM-based sequence backend
    EVM {
        /// Final destination contract that the sequencing contract calls into.
        target: Address,
        /// Sequencing contract on the destination backend that must receive the cert.
        eth_contract: Address,
    },
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct OracleTarget {
    /// Service destination of the certified call.
    pub target: OracleServiceTarget,
    /// Sequence backend this target belongs to.
    pub seq_id: SequenceBackendID,
}

impl OracleTarget {
    pub fn cipher(&self) -> Cipher {
        match self.target {
            OracleServiceTarget::EVM { .. } => Cipher::Secp256k1,
            OracleServiceTarget::LVM(_) => Cipher::Ed25519,
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
pub struct ValidatePreimage {
    pub header: OracleHeader,
    pub params: CallParams,
    pub approval: bool,
}

impl ValidatePreimage {
    const PREFIX: &'static [u8] = b"lyquor_validate_preimage_v1\0";

    pub fn to_preimage(&self) -> Vec<u8> {
        encode_object_with_prefix(Self::PREFIX, self)
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
            bytes32 topic;
            bytes32 group;
            bytes32 proposer;
            address target;
            bytes32 seqId;
            address ethContract;
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

        enum ABI {
            Lyquor,
            Eth
        }

        struct CallParams {
            address origin;
            address caller;
            string group;
            string method;
            bytes input;
            ABI abi_;
        }

        struct ValidatePreimage {
            OracleHeader header;
            CallParams params;
            bool approval; // Should always be true signed by multi-sigs that make up the final cert.
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

    impl ValidatePreimage {
        const PREFIX: &'static [u8] = b"lyquor_validate_preimage_v1\0";

        pub fn to_preimage(&self) -> Vec<u8> {
            let mut buf = Vec::from(Self::PREFIX);
            buf.extend_from_slice(&Self::abi_encode(self));
            buf
        }

        pub fn to_hash(&self) -> super::Hash {
            alloy_primitives::keccak256(&self.to_preimage()).0.into()
        }
    }

    impl From<OracleHeader> for super::OracleHeader {
        fn from(oh: OracleHeader) -> Self {
            Self {
                proposer: <[u8; 32]>::from(oh.proposer).into(),
                target: super::OracleTarget {
                    target: super::OracleServiceTarget::EVM {
                        target: oh.target,
                        eth_contract: oh.ethContract,
                    },
                    seq_id: <[u8; 32]>::from(oh.seqId).into(),
                },
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

    impl TryFrom<super::ValidatePreimage> for ValidatePreimage {
        type Error = ();
        fn try_from(om: super::ValidatePreimage) -> Result<Self, ()> {
            let topic = alloy_primitives::keccak256(
                om.params
                    .group
                    .split("::")
                    .next()
                    .unwrap_or(om.params.group.as_str())
                    .as_bytes(),
            );
            let group = alloy_primitives::keccak256(om.params.group.as_bytes());
            let (target, eth_contract) = match om.header.target.target {
                super::OracleServiceTarget::LVM(_) => return Err(()),
                super::OracleServiceTarget::EVM { target, eth_contract } => (target, eth_contract),
            };
            let params = CallParams {
                origin: om.params.origin,
                caller: om.params.caller,
                group: om.params.group,
                method: om.params.method,
                input: om.params.input.into(),
                abi_: match om.params.abi {
                    super::InputABI::Lyquor => ABI::Lyquor,
                    super::InputABI::Eth => ABI::Eth,
                },
            };
            let header = OracleHeader {
                topic: topic.into(),
                group: group.into(),
                proposer: <[u8; 32]>::from(om.header.proposer).into(),
                target,
                seqId: <[u8; 32]>::from(om.header.target.seq_id).into(),
                ethContract: eth_contract,
                configHash: <[u8; 32]>::from(om.header.config_hash).into(),
                epoch: om.header.epoch,
                nonce: <[u8; 32]>::from(om.header.nonce).into(),
            };
            Ok(Self {
                header,
                params,
                approval: om.approval,
            })
        }
    }
}
