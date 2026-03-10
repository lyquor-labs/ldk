//! Runtime oracle support for the NEAT protocol (Nonce-Epoch Autonomous Target Routing).
//!
//! ## State ownership and safety model
//! - Source does **not** own authoritative on-chain oracle state.
//! - Target owns and enforces oracle state on-chain (`config`, `epoch`, nonce set).
//! - Source keeps only a local instance-state cache for voting/liveness heuristics.
//!   LDK users can customize this behavior from instance functions (for example `add_node`,
//!   `remove_node`, and `set_threshold`).
//! - Safety is decided at Target verification time via threshold-signature checks plus
//!   epoch/nonce replay protection.
//!
//! A nonce is single-use within an epoch, so a certified call cannot be replayed after acceptance.
//!
//! ## Runtime call flow
//! Shared forward envelope:
//! ```text
//! +---------------+      +-----+      +--------------------------------------+
//! | Source Lyquid | ---> | FCO | ---> | __lyquor_submit_certified_calls(...) |
//! +---------------+      +-----+      +--------------------------------------+
//! ```
//!
//! Normal certified settlement (input carries raw input of the call + cert):
//! ```text
//! +------------------------------------+    +------------------------------------------+
//! | LVM: emit Slot with                | or | EVM: decode raw input + cert from        |
//! | oracle::certified::<topic>::...    |    | the same CallParams.input, then          |
//! |                                    |    | call ethCertifiedCall(...)               |
//! +------------------------------------+    +------------------------------------------+
//! ```
//!
//! Epoch-advance settlement (input carries raw input of the delta + cert):
//! ```text
//! +------------------------------------+    +------------------------------------------+
//! | LVM: emit Slot with                | or | EVM: decode raw input + cert from        |
//! | oracle::internal::__lyquor_...     |    | the same CallParams.input, then          |
//! |                                    |    | call ethCertifiedCall(...)               |
//! +------------------------------------+    +------------------------------------------+
//! ```
//! - Target verifies cert + epoch/nonce replay checks in both routes.
//! - Only epoch-advance settlement applies a config delta.
//!
//! Push notification path (Target -> Source nudge):
//! ```text
//! +---------------------------------+    +-----+    +------------------------------+
//! | Target emits OracleEpochAdvance | -> | FCO | -> | __lyquor_oracle_sync_targets |
//! +---------------------------------+    +-----+    +------------------------------+
//! ```
//! - Unified signal surface: backend watches the same `OracleEpochAdvance` event for both targets
//!   and drives the same FCO notification pipeline.
//! - Emit-point difference: for EVM targets the event is emitted in `ethCertifiedCall(...)` after
//!   verification; for LVM targets it is emitted on the submit path before destination Lyquid
//!   verification/execution.
//! - Common pipeline:
//!   `sequencer::eth::SlotCrawler` -> `Sequence::notify_oracle_epoch_advance()` ->
//!   `fco::NotifyOracleEpochAdvance` -> `node::LyquidProcess(OnOracleEpochAdvance)` ->
//!   `__lyquor_oracle_sync_targets`.
//! - LVM tradeoff: push nudge is decoupled from destination execution/verification, so Source may
//!   run an extra sync before destination state lands. Safety still holds because reconciliation
//!   accepts only backend-reported epoch/config-hash-consistent states.
//!
//! Pull path (`get_oracle_epoch(topic, target)`):
//! ```text
//! +-------------+      +------+      +---------------------------+
//! | VM host API | ---> | FCO  | ---> | Target query bifurcation  |
//! +-------------+      +------+      +---------------------------+
//!                                                 | LVM: __lyquor_oracle_... |
//!                                                 | EVM: SlotCrawler eth_call |
//!                                                 +---------------------------+
//! ```

use super::internal::StateAccessor;
use super::prelude::*;
use lyquor_primitives::HashBytes;
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

pub(crate) const LVM_ORACLE_ON_EPOCH_ADVANCE_METHOD: &str = "__lyquor_oracle_on_epoch_advance";
pub(crate) const ORACLE_EPOCH_VALIDATE_GROUP_SUFFIX: &str = "__epoch";

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

pub fn is_epoch_advance_params(topic: &str, params: &CallParams) -> bool {
    params.origin == Address::ZERO &&
        params.caller == Address::ZERO &&
        params.abi == lyquor_primitives::InputABI::Lyquor &&
        params.group == topic &&
        params.method == LVM_ORACLE_ON_EPOCH_ADVANCE_METHOD
}

pub(crate) fn random_cert_nonce() -> Option<HashBytes> {
    let bytes = lyquor_api::random_bytes(32).ok()?;
    let hash = Hash::from_slice(&bytes).ok()?;
    Some(hash.into())
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
            ctx: &mut _, topic: String,
        ) -> LyquidResult<(u64, $crate::lyquor_primitives::B256)> {
            let info = ctx.network.__internal.oracle_dest_epoch_info(topic.as_str());
            let config_hash: [u8; 32] = info.config_hash.into();
            Ok((info.epoch as u64, config_hash.into()))
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
            topic: String,
            payload: $crate::lyquor_primitives::Bytes
        ) -> LyquidResult<bool> {
            let wrapped = $crate::lyquor_primitives::decode_by_fields!(
                payload.as_ref(),
                cert: $crate::runtime::oracle::OracleCert,
                input_raw: $crate::lyquor_primitives::Bytes
            )
            .ok_or($crate::LyquidError::LyquorInput)?;
            if $crate::lyquor_primitives::decode_by_fields!(
                wrapped.input_raw.as_ref(),
                config_delta: $crate::runtime::oracle::OracleConfigDeltaWire
            )
            .is_none()
            {
                return Err($crate::LyquidError::LyquorInput);
            }
            let params = $crate::lyquor_primitives::CallParams {
                // Bind verification to the topic key supplied by the routed call.
                origin: $crate::lyquor_primitives::Address::ZERO,
                caller: $crate::lyquor_primitives::Address::ZERO,
                group: topic.clone(),
                method: "__lyquor_oracle_on_epoch_advance".into(),
                input: wrapped.input_raw,
                abi: $crate::lyquor_primitives::InputABI::Lyquor,
            };
            if !ctx
                .network
                .__internal
                .oracle_dest(topic.as_str())
                .verify(ctx.lyquid_id, params, &wrapped.cert)
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
