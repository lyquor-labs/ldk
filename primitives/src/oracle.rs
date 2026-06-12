use super::*;

/// Destination class for an oracle-certified call.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum OracleServiceTarget {
    /// Lyquor network function destination.
    LVM(LyquidID),
    /// EVM-based sequence backend destination.
    EVM {
        /// Final destination contract that the sequencing contract calls into.
        target: Address,
        /// Sequencing contract on the destination backend that must receive the cert.
        eth_contract: Address,
    },
}

/// Fully qualified oracle destination, including the sequence backend namespace.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct OracleTarget {
    /// Service destination of the certified call.
    pub target: OracleServiceTarget,
    /// Sequence backend this target belongs to.
    pub seq_id: SequenceBackendID,
}

impl OracleTarget {
    /// Return the signature cipher expected for certificates targeting this destination.
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

/// Epoch metadata known by an oracle source or destination.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleEpochInfo {
    /// Current epoch number.
    pub epoch: u32,
    /// Current oracle config hash.
    pub config_hash: HashBytes,
    /// Number of config changes materialized in this epoch.
    pub change_count: u32,
    /// Optional full config payload when requested by the caller.
    pub config: Option<OracleConfig>,
}

/// Small signer index used inside oracle certificates.
pub type SignerID = u32;

/// Oracle signer entry in a config.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleSigner {
    /// Stable signer index used by signatures and deltas.
    pub id: SignerID,
    /// Public key bytes in the cipher selected by the target.
    pub key: Bytes,
}

/// Oracle committee config.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleConfig {
    /// Committee signer set.
    pub committee: Vec<OracleSigner>,
    /// Number of valid signatures required to certify a call.
    pub threshold: u16,
}

impl OracleConfig {
    /// Hash this config with the native Lyquor serialization.
    pub fn to_hash(&self) -> Hash {
        blake3::hash(&encode_object(self))
    }
}

/// Incremental config update for an oracle committee.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleConfigDelta {
    /// Signers to add or replace.
    pub upsert: Vec<OracleSigner>,
    /// Signer IDs to remove.
    pub remove: Vec<SignerID>,
    /// Optional threshold update.
    pub threshold: Option<u16>,
}

/// Signed preimage for oracle validation votes.
#[derive(Serialize, Deserialize)]
pub struct ValidatePreimage {
    /// Certificate header being approved or rejected.
    pub header: OracleHeader,
    /// Call parameters being certified.
    pub params: CallParams,
    /// Validation decision. `true` means approval.
    pub approval: bool,
}

impl ValidatePreimage {
    const PREFIX: &'static [u8] = b"lyquor_validate_preimage_v1\0";

    /// Return the domain-separated serialized preimage bytes.
    pub fn to_preimage(&self) -> Vec<u8> {
        encode_object_with_prefix(Self::PREFIX, self)
    }

    /// Hash the validation preimage.
    pub fn to_hash(&self) -> Hash {
        blake3::hash(&self.to_preimage())
    }
}

/// Oracle certificate that could be sequenced.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleCert {
    pub header: OracleHeader,
    /// Signers for the signatures in order.
    pub signers: Vec<SignerID>,
    /// Vote signatures.
    pub signatures: Vec<Bytes>,
}

pub mod eth {
    use crate::{Address, decode_by_fields};
    use alloy_sol_types::{SolValue, sol};
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
            bytes32 nodeID;
        }

        #[derive(Default)]
        struct OracleConfig {
            OracleSigner[] committee;
            uint16 threshold;
        }

        #[derive(Default)]
        struct OracleConfigDelta {
            OracleSigner[] upsert;
            uint32[] remove;
            bool thresholdChanged;
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
        /// Hash this config with Ethereum ABI encoding.
        pub fn to_hash(&self) -> super::Hash {
            alloy_primitives::keccak256(SolValue::abi_encode(self)).0.into()
        }
    }

    impl TryFrom<super::OracleConfigDelta> for OracleConfigDelta {
        type Error = ();

        fn try_from(delta: super::OracleConfigDelta) -> Result<Self, Self::Error> {
            let upsert = delta
                .upsert
                .into_iter()
                .map(|signer| {
                    let key = signer.key.as_ref();
                    if key.len() != 32 {
                        return Err(());
                    }
                    let node_id = <[u8; 32]>::try_from(key).map_err(|_| ())?.into();
                    Ok(OracleSigner {
                        id: signer.id,
                        nodeID: node_id,
                    })
                })
                .collect::<Result<Vec<_>, ()>>()?;

            Ok(Self {
                upsert,
                remove: delta.remove,
                thresholdChanged: delta.threshold.is_some(),
                threshold: delta.threshold.unwrap_or(0),
            })
        }
    }

    impl ValidatePreimage {
        const PREFIX: &'static [u8] = b"lyquor_validate_preimage_v1\0";

        /// Return the Ethereum ABI domain-separated preimage bytes.
        pub fn to_preimage(&self) -> Vec<u8> {
            let mut buf = Vec::from(Self::PREFIX);
            buf.extend_from_slice(&SolValue::abi_encode(self));
            buf
        }

        /// Hash the Ethereum ABI validation preimage.
        pub fn to_hash(&self) -> super::Hash {
            alloy_primitives::keccak256(self.to_preimage()).0.into()
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
                    .map(|s| {
                        let key = s.key;
                        OracleSigner {
                            id: s.id,
                            nodeID: <[u8; 32]>::try_from(key.as_ref()).unwrap().into(),
                        }
                    })
                    .collect(),
                threshold: oc.threshold,
            }
        }
    }

    impl From<OracleConfig> for super::OracleConfig {
        fn from(oc: OracleConfig) -> Self {
            Self {
                committee: oc
                    .committee
                    .into_iter()
                    .map(|s| super::OracleSigner {
                        id: s.id,
                        key: s.nodeID.as_slice().to_vec().into(),
                    })
                    .collect(),
                threshold: oc.threshold,
            }
        }
    }

    impl TryFrom<super::ValidatePreimage> for ValidatePreimage {
        type Error = ();
        fn try_from(om: super::ValidatePreimage) -> Result<Self, ()> {
            let params = om.params;
            let is_epoch_advance = params.origin == Address::ZERO &&
                params.abi == super::InputABI::Lyquor &&
                params.group == "oracle::internal" &&
                params.method == "__lyquor_oracle_on_epoch_advance";
            let (topic, input) = if is_epoch_advance {
                let payload = decode_by_fields!(
                    params.input.as_ref(),
                    topic: String,
                    config_delta: super::OracleConfigDelta,
                    change_count: u32
                )
                .ok_or(())?;
                let config_delta = OracleConfigDelta::try_from(payload.config_delta)?;
                let topic = payload.topic;
                let input = (config_delta, payload.change_count).abi_encode_params();
                (topic, input)
            } else {
                (
                    params
                        .group
                        .split_once("::")
                        .map(|(topic, _)| topic)
                        .unwrap_or(params.group.as_str())
                        .to_string(),
                    params.input.to_vec(),
                )
            };
            let topic_hash = alloy_primitives::keccak256(topic.as_bytes());
            let group_hash = alloy_primitives::keccak256(params.group.as_bytes());
            let (target, eth_contract) = match om.header.target.target {
                super::OracleServiceTarget::LVM(_) => return Err(()),
                super::OracleServiceTarget::EVM { target, eth_contract } => (target, eth_contract),
            };
            let params = CallParams {
                origin: params.origin,
                caller: params.caller,
                group: params.group,
                method: params.method,
                input: input.into(),
                abi_: match params.abi {
                    super::InputABI::Lyquor => ABI::Lyquor,
                    super::InputABI::Eth => ABI::Eth,
                },
            };
            let header = OracleHeader {
                topic: topic_hash,
                group: group_hash,
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
