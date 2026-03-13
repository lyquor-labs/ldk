//! NEAT: Runtime Oracle Protocol
//!
//! Implementation of NEAT (Nonce-Epoch with Arbitrary Targets), a software-defined,
//! self-governed oracle protocol.
//!
//! ## High-Level Model
//! - Source-side oracle state lives in builtin network state and is keyed by the actual target.
//!   It is the shared staged intent used for voting.
//! - Destination state is authoritative. Each target topic owns the active config, config hash,
//!   epoch, consumed `change_count`, and replay-protection nonce set.
//! - Ordinary certified calls stay off-chain until final settlement. Oracle coordination only adds
//!   explicit epoch-boundary settlement.
//!
//! The epoch-boundary flow is bidirectional:
//! - `advance_epoch(...)` goes from source to target and settles one exact staged source-op prefix
//!   on the target.
//! - `finalize_epoch(...)` goes from target back to source and moves source forward by consuming
//!   exactly the prefix that target actually settled.
//!
//! This keeps the target canonical for active config selection while still letting source keep the
//! shared staged voting baseline.
//!
//! ## Routing
//! Source produces a certified envelope and submits it through FCO:
//! ```text
//! Source Lyquid -> FCO -> __lyquor_submit_certified_calls(...)
//! ```
//!
//! TODO: the source identity should not rely on `caller` alone. `LyquidID` is not globally
//! unique across sequencing backends, so the source-side identity carried by protocol-internal
//! calls should eventually include the sequencing backend ID as well.
//!
//! The certified envelope shape is independent of the execution target:
//! - `CallParams.input = (cert, input_raw)`
//! - `input_raw` is the signed payload for the destination path
//!
//! There are three protocol routes:
//! - **Normal certified call**:
//!   destination verifies the cert against the active config and executes the user call.
//! - **Epoch advance**:
//!   destination verifies a source-certified next-epoch transition and, if valid, advances to the
//!   next target epoch.
//! - **Epoch finalize**:
//!   source verifies that enough nodes observed the settled target fact and then applies that
//!   settled epoch back into source staging state.
//!
//! Epoch advance is a protocol-internal destination route:
//! - signed params use `group = "oracle::internal"`
//! - method = `__lyquor_oracle_on_epoch_advance`
//! - payload = `(topic, config_delta, change_count)`
//!
//! Epoch finalize is a protocol-internal source route:
//! - signed params use `group = "<topic>::__epoch"`
//! - method = `__lyquor_oracle_on_epoch_finalize`
//! - payload = `(target, target_state)`
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
//! Target observations come from `fetch_oracle_info(topic, target, full_config)`, which returns
//! `(epoch, config_hash, change_count)` and may additionally include the authoritative target
//! config for debugging or inspection.

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
pub use source::{OracleConfig, OracleSrc, StateVar};

pub(crate) const ADVANCE_EPOCH_METHOD: &str = "__lyquor_oracle_on_epoch_advance";
pub(crate) const FINALIZE_EPOCH_METHOD: &str = "__lyquor_oracle_on_epoch_finalize";
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

pub(crate) fn fetch_target_epoch_info(
    topic: &str, target: OracleTarget, full_config: bool,
) -> LyquidResult<Option<OracleEpochInfo>> {
    lyquor_api::fetch_oracle_info(topic.to_string(), target, full_config)
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
            u32,
            $crate::lyquor_primitives::Bytes
        )> {
            let info = ctx
                .network
                .__internal
                .oracle_dest_epoch_info(topic.as_str(), full_config);
            Ok((
                info.epoch as u64,
                <[u8; 32]>::from(info.config_hash).into(),
                info.change_count,
                info.config
                    .map(|config| $crate::lyquor_primitives::encode_object(&config).into())
                    .unwrap_or_default(),
            ))
        }

        // Propose to advance the epoch and submit all staged changes to the oracle target state.
        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_advance_epoch(
            ctx: &mut _, topic: String, target_addr: $crate::lyquor_primitives::Address, is_evm: bool,
        ) -> LyquidResult<bool> {
            let target = match is_evm {
                true => $crate::runtime::oracle::oracle_target_evm_from_address(target_addr)?,
                false => $crate::runtime::oracle::oracle_target_lvm_from_address(target_addr)?,
            };
            let call = $crate::runtime::oracle::StateVar::new(topic.as_str()).advance_epoch(&mut ctx, target)?;
            match call {
                Some(call) => {
                    $crate::runtime::lyquor_api::submit_call(call, false)?;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        // Submit a source-side certified finalize-epoch call for an oracle target.
        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_finalize_epoch(
            ctx: &mut _, topic: String, target_addr: $crate::lyquor_primitives::Address, is_evm: bool,
        ) -> LyquidResult<bool> {
            let target = match is_evm {
                true => $crate::runtime::oracle::oracle_target_evm_from_address(target_addr)?,
                false => $crate::runtime::oracle::oracle_target_lvm_from_address(target_addr)?,
            };
            let call = $crate::runtime::oracle::StateVar::new(topic.as_str()).finalize_epoch(&mut ctx, target)?;
            match call {
                Some(call) => {
                    $crate::runtime::lyquor_api::submit_call(call, false)?;
                    Ok(true)
                }
                None => Ok(false),
            }
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
                config_delta: $crate::runtime::oracle::OracleConfigDeltaWire,
                change_count: u32
            )
            .ok_or($crate::LyquidError::LyquorInput)?;
            if !ctx
                .network
                .__internal
                .oracle_dest(payload.topic.as_str())
                .verify_epoch_advance(
                    ctx.lyquid_id,
                    ctx.caller,
                    payload.topic.as_str(),
                    &payload.config_delta,
                    payload.change_count,
                    &cert,
                )
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
                // Route exists for epoch voting. Request path short-circuits to
                // `true` for protocol-validated epoch params before user body.
                Ok(true)
            }

            #[$crate::method::network(group = oracle::certified::$name::__epoch)]
            fn __lyquor_oracle_on_epoch_finalize(
                ctx: &mut _,
                target: $crate::runtime::oracle::OracleTarget,
                target_state: $crate::runtime::oracle::OracleEpochInfo,
            ) -> LyquidResult<bool> {
                Ok(ctx
                    .network
                    .__internal
                    .oracle_src_mut(stringify!($name))
                    .finalize_epoch(target.target, target_state))
            }
        }

        $crate::__lyquid_define_oracle_epoch_vote_handlers!($($rest)*);
    };
    (($($_other:tt)*) $($rest:tt)*) => {
        $crate::__lyquid_define_oracle_epoch_vote_handlers!($($rest)*);
    };
    () => {};
}
