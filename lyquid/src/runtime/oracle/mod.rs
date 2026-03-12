//! NEAT: Runtime Oracle Protocol
//!
//! Implementation of NEAT (Nonce-Epoch Autonomous Target Routing), a software-defined,
//! self-governed oracle protocol.
//!
//! ## State Model
//! - Source-side oracle state is a local instance-state cache. It drives proposal, validation, and
//!   staging of committee changes, but it is not authoritative.
//! - Destination state is authoritative. Each target topic owns the active config, config hash,
//!   epoch, and replay-protection nonce set.
//! - Safety is decided only at destination verification time: certificate signatures, target
//!   binding, config binding, epoch transition rules, and nonce replay checks are enforced there.
//!
//! A certified call nonce is single-use within an epoch, so an accepted call cannot be replayed.
//!
//! ## Forward Path
//! Source produces a certified envelope and submits it through FCO:
//! ```text
//! Source Lyquid -> FCO -> __lyquor_submit_certified_calls(...)
//! ```
//!
//! The certified envelope shape is independent of the execution target:
//! - `CallParams.input = (cert, input_raw)`
//! - `input_raw` is the signed payload for the destination path
//!
//! There are two settlement routes:
//! - **Normal certified call**:
//!   destination verifies the cert against the active config, requires the current epoch, and then
//!   executes the user call.
//! - **Epoch advance**:
//!   destination is the only path that may advance to the next epoch. It verifies the cert against
//!   the current config, may apply a staged config delta, and does not execute a user call body.
//!
//! Epoch advance is intentionally a protocol-internal route:
//! - signed params use `group = "oracle::internal"`
//! - method = `__lyquor_oracle_on_epoch_advance`
//! - payload = `(topic, config_delta)`
//! - `config_delta` may be empty for an explicit rollover without reconfiguration; destination
//!   still requires the usual next-epoch nonce threshold in that case.
//!
//! ## Backend vs Target
//! A sequencing backend is the source of ordering/finality for certified calls. A target is where
//! the certified call is actually executed.
//!
//! Under one sequencing backend, NEAT supports two execution targets:
//! - LVM target:
//!   the submitted slot preserves the Lyquor call and the destination runtime verifies it through
//!   [`OracleDest`] before mutating state.
//! - EVM target:
//!   the sequencing contract decodes the same `(cert, input_raw)` envelope and routes it through
//!   `ethCertifiedCall(...)`, where Solidity mirrors the destination verification/update logic.
//!
//! ## Source Validation and Sync
//! - Source pre-validation checks that the proposed destination call matches the local staged view
//!   for the topic/target before signing.
//! - Destination emits `OracleEpochAdvance` as a nudge so source instances know to refresh their
//!   local cache.
//! - For verified EVM dispatch, the event carries the canonical topic hash.
//! - For the raw LVM fallback path, the event carries `keccak256(group)` because the contract
//!   cannot decode the Lyquor payload topic there.
//! - Source reconciliation still trusts only sequencing-backend-reported target state via
//!   `get_oracle_epoch(topic, target, full_config)`, which returns `(epoch, config_hash)` and may
//!   additionally include the authoritative target config.

use super::internal::StateAccessor;
use super::prelude::*;
pub use lyquor_primitives::oracle::OracleConfigDelta as OracleConfigDeltaWire;
pub use lyquor_primitives::oracle::{
    OracleCert, OracleEpochInfo, OracleHeader, OracleServiceTarget, OracleTarget, SignerID,
};

mod dest;
mod protocol;
mod source;

pub use dest::OracleDest;
pub use protocol::{
    CertifiedCallParams, Proposal, ProposalAggregation, ProposalAggregationContext, ProposalInput, ProposeRequest,
    ProposeResponse, ValidateAggregation, ValidateRequest, ValidateResponse,
};
pub use source::{OracleConfig, OracleSrc, SrcWrapper};

pub(crate) const ADVANCE_EPOCH_METHOD: &str = "__lyquor_oracle_on_epoch_advance";
pub(crate) const ADVANCE_EPOCH_GROUP_SUFFIX: &str = "__epoch";

pub fn oracle_target_evm_from_address(contract: Address) -> LyquidResult<OracleTarget> {
    if contract == Address::ZERO {
        return Err(LyquidError::LyquorRuntime(
            "EVM contract address cannot be zero.".into(),
        ));
    }
    let seq_id = lyquor_api::sequence_backend_id()?;
    let eth_contract = match lyquor_api::eth_contract()? {
        Some(eth_contract) => eth_contract,
        None => {
            return Err(LyquidError::LyquorRuntime("Lyquid does not support EVM target.".into()));
        }
    };
    Ok(OracleTarget {
        target: OracleServiceTarget::EVM {
            target: contract,
            eth_contract,
        },
        seq_id,
    })
}

pub fn oracle_target_lvm_from_address(lyquid_id: Address) -> LyquidResult<OracleTarget> {
    if lyquid_id == Address::ZERO {
        return Err(LyquidError::LyquorRuntime("LVM LyquidID cannot be zero.".into()));
    }
    let seq_id = lyquor_api::sequence_backend_id()?;
    Ok(OracleTarget {
        target: OracleServiceTarget::LVM(lyquid_id.into()),
        seq_id,
    })
}

/// Read-only access to Source-side oracle cache in builtin instance state.
pub trait OracleSrcReadContext: crate::runtime::internal::sealed::Sealed {
    fn instance_internal_state(&self) -> &crate::runtime::internal::BuiltinInstanceState;
}

/// Mutable access to Source-side oracle cache in builtin instance state.
pub trait OracleSrcStateContext: OracleSrcReadContext {
    fn instance_internal_state_mut(&mut self) -> &mut crate::runtime::internal::BuiltinInstanceState;
}

impl<S: StateAccessor, I: StateAccessor> OracleSrcReadContext for crate::runtime::InstanceContextImpl<S, I> {
    fn instance_internal_state(&self) -> &crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

impl<S: StateAccessor, I: StateAccessor> OracleSrcStateContext for crate::runtime::InstanceContextImpl<S, I> {
    fn instance_internal_state_mut(&mut self) -> &mut crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

impl<S: StateAccessor, I: StateAccessor> OracleSrcReadContext for crate::runtime::upc::RequestContextImpl<S, I> {
    fn instance_internal_state(&self) -> &crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

impl<S: StateAccessor, I: StateAccessor> OracleSrcStateContext for crate::runtime::upc::RequestContextImpl<S, I> {
    fn instance_internal_state_mut(&mut self) -> &mut crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

impl<S: StateAccessor, I: StateAccessor> OracleSrcReadContext for crate::runtime::ImmutableInstanceContextImpl<S, I> {
    fn instance_internal_state(&self) -> &crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_define_oracle_internal_methods {
    () => {
        // Get the epoch info from the internal OracleDest state (executed at the target Lyquid).
        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_dest_epoch_info(
            ctx: &mut _, topic: String, full_config: bool,
        ) -> LyquidResult<(
            u64,
            $crate::lyquor_primitives::B256,
            Vec<u32>,
            Vec<$crate::lyquor_primitives::Bytes>,
            u16
        )> {
            let info = ctx.network.__internal.oracle_dest_epoch_info(topic.as_str(), full_config);
            let (committee_ids, committee_keys, threshold) = match info.config {
                Some(config) => {
                    let committee_ids = config.committee.iter().map(|signer| signer.id).collect();
                    let committee_keys = config.committee.into_iter().map(|signer| signer.key).collect();
                    (committee_ids, committee_keys, config.threshold)
                }
                None => (Vec::new(), Vec::new(), 0),
            };
            Ok((
                info.epoch as u64,
                <[u8; 32]>::from(info.config_hash).into(),
                committee_ids,
                committee_keys,
                threshold,
            ))
        }

        // Propose to advance the epoch and submit all staged changes to the oracle target state.
        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_advance_epoch_evm(
            ctx: &mut _, topic: String, seq_contract: $crate::lyquor_primitives::Address,
        ) -> LyquidResult<bool> {
            let target = $crate::runtime::oracle::oracle_target_evm_from_address(seq_contract)?;
            let call = $crate::runtime::oracle::SrcWrapper::new(topic.as_str()).advance_epoch(&mut ctx, target)?;
            match call {
                Some(call) => {
                    $crate::runtime::lyquor_api::submit_call(call, false)?;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        // Propose to advance the epoch and submit all staged changes to the oracle target state.
        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_advance_epoch_lvm(
            ctx: &mut _, topic: String, lyquid_id: $crate::lyquor_primitives::Address,
        ) -> LyquidResult<bool> {
            let target = $crate::runtime::oracle::oracle_target_lvm_from_address(lyquid_id)?;
            let call = $crate::runtime::oracle::SrcWrapper::new(topic.as_str()).advance_epoch(&mut ctx, target)?;
            match call {
                Some(call) => {
                    $crate::runtime::lyquor_api::submit_call(call, false)?;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        // Refresh the source Lyquid's local knowledge of target state.
        #[$crate::method::instance(group = oracle::internal)]
        fn __lyquor_oracle_sync_targets(ctx: &mut _) -> LyquidResult<bool> {
            use $crate::runtime::oracle::OracleSrcStateContext as _;
            ctx.instance_internal_state_mut().oracle_src_sync_targets();
            Ok(true)
        }

        // LVM target epoch advance method.
        #[$crate::method::network(group = oracle::internal)]
        fn __lyquor_oracle_on_epoch_advance(
            ctx: &mut _,
            cert: $crate::runtime::oracle::OracleCert,
            input_raw: $crate::lyquor_primitives::Bytes,
        ) -> LyquidResult<bool> {
            let payload = $crate::lyquor_primitives::decode_by_fields!(
                input_raw.as_ref(),
                topic: String,
                config_delta: $crate::runtime::oracle::OracleConfigDeltaWire
            )
            .ok_or($crate::LyquidError::LyquorInput)?;
            if !ctx
                .network
                .__internal
                .oracle_dest(payload.topic.as_str())
                .verify_epoch_advance(ctx.lyquid_id, payload.topic.as_str(), &payload.config_delta, &cert)
            {
                return Err($crate::LyquidError::InputCert);
            }
            Ok(true)
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_define_oracle_epoch_vote_handlers {
    ((oracle $name:ident) $($rest:tt)*) => {
        mod $name {
            use super::*;

            #[$crate::method::instance(group = oracle::single_phase::$name::__epoch)]
            fn validate(
                _ctx: &mut _,
                _params: CallParams,
                _extra: Bytes,
                _target: OracleTarget
            ) -> LyquidResult<bool> {
                // Route exists for epoch-advance voting. Request path short-circuits to `true`
                // for epoch-advance params before user body.
                Ok(true)
            }
        }

        $crate::__lyquid_define_oracle_epoch_vote_handlers!($($rest)*);
    };
    (($($_other:tt)*) $($rest:tt)*) => {
        $crate::__lyquid_define_oracle_epoch_vote_handlers!($($rest)*);
    };
    () => {};
}
