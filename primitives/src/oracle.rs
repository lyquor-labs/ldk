use super::*;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug, Hash)]
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

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug, Hash)]
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

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct OracleEpochInfo {
    pub epoch: u32,
    pub config_hash: HashBytes,
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleConfigDelta {
    pub upsert: Vec<OracleSigner>,
    pub remove: Vec<SignerID>,
    pub threshold: Option<u16>,
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
    /// Signers for the signatures in order.
    pub signers: Vec<SignerID>,
    /// Vote signatures.
    pub signatures: Vec<Bytes>,
}

/// Oracle call groups are represented as `<topic>[::<suffix...>]`.
#[inline]
pub fn topic_from_group(group: &str) -> &str {
    group.split_once("::").map(|(topic, _)| topic).unwrap_or(group)
}

/// Transport prefix used by the sequencing contract when forwarding certified calls.
pub const ORACLE_CERTIFIED_GROUP_PREFIX: &str = "oracle::certified::";

/// Convert a dispatch-time certified call group into its topic key.
///
/// The input may be either:
/// - a raw oracle group (`<topic>[::<suffix...>]`), or
/// - a sequencer-dispatched group (`oracle::certified::<topic>[::<suffix...>]`).
#[inline]
pub fn topic_from_dispatch_group(group: &str) -> &str {
    let group = group.strip_prefix(ORACLE_CERTIFIED_GROUP_PREFIX).unwrap_or(group);
    topic_from_group(group)
}

pub mod eth {
    use crate::{Address, decode_by_fields};
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
        pub fn to_hash(&self) -> super::Hash {
            alloy_primitives::keccak256(OracleConfig::abi_encode(self)).0.into()
        }
    }

    impl TryFrom<super::OracleConfigDelta> for OracleConfigDelta {
        type Error = ();

        fn try_from(delta: super::OracleConfigDelta) -> Result<Self, Self::Error> {
            let upsert = delta
                .upsert
                .into_iter()
                .map(|signer| {
                    let key = signer.key.as_ref().try_into().map_err(|_| ())?;
                    Ok(OracleSigner { id: signer.id, key })
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

        pub fn to_preimage(&self) -> Vec<u8> {
            let mut buf = Vec::from(Self::PREFIX);
            buf.extend_from_slice(&Self::abi_encode(self));
            buf
        }

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
                    .map(|s| OracleSigner {
                        id: s.id,
                        key: s.key.as_ref().try_into().unwrap(),
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
                        key: s.key.to_vec().into(),
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
                params.caller == Address::ZERO &&
                params.abi == super::InputABI::Lyquor &&
                params.group == "oracle::internal" &&
                params.method == "__lyquor_oracle_on_epoch_advance";
            let (topic, input) = if is_epoch_advance {
                let payload = decode_by_fields!(
                    params.input.as_ref(),
                    topic: String,
                    config_delta: super::OracleConfigDelta
                )
                .ok_or(())?;
                let config_delta = OracleConfigDelta::try_from(payload.config_delta)?;
                let topic = payload.topic;
                let input = OracleConfigDelta::abi_encode(&config_delta);
                (topic, input)
            } else {
                (
                    super::topic_from_group(params.group.as_str()).to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_from_group_uses_first_segment() {
        assert_eq!(topic_from_group("price_feed"), "price_feed");
        assert_eq!(topic_from_group("price_feed::two_phase"), "price_feed");
    }

    #[test]
    fn topic_from_dispatch_group_accepts_both_forms() {
        assert_eq!(topic_from_dispatch_group("price_feed"), "price_feed");
        assert_eq!(topic_from_dispatch_group("price_feed::two_phase"), "price_feed");
        assert_eq!(topic_from_dispatch_group("oracle::certified::price_feed"), "price_feed");
        assert_eq!(
            topic_from_dispatch_group("oracle::certified::price_feed::two_phase"),
            "price_feed"
        );
    }
}
