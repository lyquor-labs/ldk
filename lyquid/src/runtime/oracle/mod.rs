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

const ADVANCE_EPOCH_METHOD: &str = "__lyquor_oracle_on_epoch_advance";
const FINALIZE_EPOCH_METHOD: &str = "__lyquor_oracle_on_epoch_finalize";
const EPOCH_GROUP_SUFFIX: &str = "__epoch";

// TODO: allow a different sequence backend ID from this Lyquid's environment.
pub fn oracle_target_from_address(target_addr: Address, is_evm: bool) -> LyquidResult<OracleTarget> {
    let seq_id = lyquor_api::sequence_backend_id()?;
    let target = if is_evm {
        let eth_contract = match lyquor_api::eth_contract()? {
            Some(eth_contract) => eth_contract,
            None => {
                return Err(LyquidError::LyquorRuntime("Lyquid does not support EVM target.".into()));
            }
        };
        OracleServiceTarget::EVM {
            target: target_addr,
            eth_contract,
        }
    } else {
        OracleServiceTarget::LVM(target_addr.into())
    };
    Ok(OracleTarget { target, seq_id })
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
            let target = $crate::runtime::oracle::oracle_target_from_address(target_addr, is_evm)?;
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
            let target = $crate::runtime::oracle::oracle_target_from_address(target_addr, is_evm)?;
            let call = $crate::runtime::oracle::StateVar::new(topic.as_str()).finalize_epoch(&mut ctx, target)?;
            match call {
                Some(call) => {
                    $crate::runtime::lyquor_api::submit_call(call, false)?;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        // Initialize source-side oracle staging for a target. This does not touch target state;
        // the topic becomes active only after the first epoch advance/finalize round settles.
        #[$crate::method::network(group = oracle::internal, export = eth)]
        fn __lyquor_oracle_on_initialize(
            ctx: &mut _,
            topic: String,
            target_addr: $crate::lyquor_primitives::Address,
            is_evm: bool,
            committee: Vec<$crate::lyquor_primitives::NodeID>,
            threshold: u16,
        ) -> LyquidResult<bool> {
            let target = $crate::runtime::oracle::oracle_target_from_address(target_addr, is_evm)?;
            Ok(ctx
                .network
                .__internal
                .oracle_src_mut(topic.as_str())
                .initialize(target, committee, threshold))
        }

        // LVM target-side epoch advance method.
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
                target_info: $crate::runtime::oracle::OracleEpochInfo,
            ) -> LyquidResult<bool> {
                Ok(ctx
                    .network
                    .__internal
                    .oracle_src_mut(stringify!($name))
                    .finalize_epoch(target, target_info))
            }
        }

        $crate::__lyquid_define_oracle_epoch_vote_handlers!($($rest)*);
    };
    (($($_other:tt)*) $($rest:tt)*) => {
        $crate::__lyquid_define_oracle_epoch_vote_handlers!($($rest)*);
    };
    () => {};
}
