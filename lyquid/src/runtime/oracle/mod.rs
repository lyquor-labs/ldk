//! NEAT Protocol (Nonce-Epoch Autonomous Target Routing).
//!
//! Core property:
//! - Source does **not** maintain authoritative on-chain oracle state.
//! - Target maintains and enforces oracle state on-chain (config, epoch, nonce set).
//!
//! Source keeps only a local cache in instance state for voting/liveness. Safety is decided at
//! Target verification time with epoch/nonce replay checks and threshold-signature checks.
//! Nonces provide one-time validity of certified calls within an epoch.
//!
//! Runtime forwarding/verification flow:
//! - Normal certified-call Source -> Target settlement (no config delta):
//!   - LVM Target: Source Lyquid -> Sequencer/FCO ->
//!     `oracle::certified::<topic>::<group> fn <method>` on destination Lyquid.
//!   - EVM Target: Source Lyquid -> Sequencer/FCO -> ETH backend ->
//!     `ethCertifiedCall(...)` on destination sequencing contract.
//!   - Target verifies cert + epoch/nonce replay checks; config is unchanged.
//! - Epoch-advance Source -> Target settlement (`advance_epoch()` with config delta in signed
//!   `CallParams.input`):
//!   - LVM Target: Source Lyquid -> Sequencer/FCO ->
//!     protocol-routed `oracle::internal::__lyquor_oracle_on_epoch_advance(topic, payload)`.
//!   - EVM Target: Source Lyquid -> Sequencer/FCO -> ETH backend ->
//!     `ethCertifiedCall(...)`.
//!   - Target verifies cert + replay checks and applies the delta.
//! - Target -> Source nudge (push):
//!   - EVM Target: backend observes `OracleEpochAdvance(topic)` emitted from
//!     `ethCertifiedCall(...)` after verification.
//!   - LVM Target: backend observes `OracleEpochAdvance(topic)` emitted from
//!     `__lyquor_submit_certified_calls(...)` for epoch-advance submissions.
//!   - LVM tradeoff: this nudge is decoupled from destination Lyquid execution/verification, so
//!     Source may occasionally run an extra sync before the corresponding destination state lands.
//!     Safety is preserved because Source reconciliation accepts only backend-reported
//!     epoch/config-hash-consistent states.
//!   - Common pipeline:
//!     `sequencer::eth::SlotCrawler` -> `Sequence::notify_oracle_epoch_advance()` ->
//!     `fco::NotifyOracleEpochAdvance` ->
//!     `node::LyquidProcess(OnOracleEpochAdvance)` -> `__lyquor_oracle_sync_targets`.
//! - Pull query forwarding (`get_oracle_epoch(topic, target)`):
//!   - LVM Target: VM host API -> Sequencer/FCO -> node `LyquidPool::GetOracleEpoch` ->
//!     destination `__lyquor_oracle_dest_epoch_info`.
//!   - EVM Target: VM host API -> Sequencer/FCO ->
//!     backend `SlotCrawler::GetOracleEpoch` (`eth_call`).

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
pub use source::{OracleConfig, OracleSrc, SrcWrapper, oracle_target_evm_from_address, oracle_target_lvm_from_address};

pub(crate) const LVM_ORACLE_ON_EPOCH_ADVANCE_METHOD: &str = "__lyquor_oracle_on_epoch_advance";
pub(crate) const ORACLE_EPOCH_VALIDATE_GROUP_SUFFIX: &str = "__epoch";

pub(crate) fn random_cert_nonce() -> Option<HashBytes> {
    let bytes = lyquor_api::random_bytes(32).ok()?;
    let hash = Hash::from_slice(&bytes).ok()?;
    Some(hash.into())
}

/// Contexts that can access Source-side oracle local state.
pub trait OracleSrcReadContext: crate::runtime::internal::sealed::Sealed {
    fn instance_internal_state(&self) -> &crate::runtime::internal::BuiltinInstanceState;
}

/// Contexts that can mutate Source-side oracle local state.
pub trait OracleSrcStateContext: OracleSrcReadContext {
    fn instance_internal_state_mut(&mut self) -> &mut crate::runtime::internal::BuiltinInstanceState;
}

impl<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor> OracleSrcReadContext
    for crate::runtime::InstanceContextImpl<S, I>
{
    fn instance_internal_state(&self) -> &crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

impl<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor> OracleSrcStateContext
    for crate::runtime::InstanceContextImpl<S, I>
{
    fn instance_internal_state_mut(&mut self) -> &mut crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

impl<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor> OracleSrcReadContext
    for crate::runtime::upc::RequestContextImpl<S, I>
{
    fn instance_internal_state(&self) -> &crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

impl<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor> OracleSrcStateContext
    for crate::runtime::upc::RequestContextImpl<S, I>
{
    fn instance_internal_state_mut(&mut self) -> &mut crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

impl<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor> OracleSrcReadContext
    for crate::runtime::ImmutableInstanceContextImpl<S, I>
{
    fn instance_internal_state(&self) -> &crate::runtime::internal::BuiltinInstanceState {
        crate::runtime::internal::builtin_instance_state().expect("oracle: failed to access builtin instance state.")
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_define_oracle_internal_methods {
    () => {
        #[$crate::method::instance(group = oracle::internal)]
        fn __lyquor_oracle_dest_epoch_info(
            ctx: &mut _, topic: String,
        ) -> LyquidResult<$crate::lyquor_primitives::oracle::OracleEpochInfo> {
            Ok(ctx.network.__internal.oracle_dest_epoch_info(topic.as_str()))
        }

        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_src_epoch_info_evm(
            ctx: &mut _, topic: String, target: $crate::lyquor_primitives::Address,
        ) -> LyquidResult<u64> {
            use $crate::runtime::oracle::OracleSrcStateContext as _;
            let target = $crate::runtime::oracle::oracle_target_evm_from_address(target)?;
            let state = $crate::runtime::lyquor_api::get_oracle_epoch(topic.clone(), target)?;
            if let Some(v) = state {
                let epoch = v.epoch as u64;
                ctx.instance_internal_state_mut()
                    .oracle_src_mut(topic.as_str())
                    .sync_current_state_with_info(target.target, v);
                Ok(epoch)
            } else {
                Ok(0)
            }
        }

        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_src_epoch_info_lvm(
            ctx: &mut _, topic: String, target: $crate::lyquor_primitives::Address,
        ) -> LyquidResult<u64> {
            use $crate::runtime::oracle::OracleSrcStateContext as _;
            let target = $crate::runtime::oracle::oracle_target_lvm_from_address(ctx.lyquid_id, target)?;
            let state = $crate::runtime::lyquor_api::get_oracle_epoch(topic.clone(), target)?;
            if let Some(v) = state {
                let epoch = v.epoch as u64;
                ctx.instance_internal_state_mut()
                    .oracle_src_mut(topic.as_str())
                    .sync_current_state_with_info(target.target, v);
                Ok(epoch)
            } else {
                Ok(0)
            }
        }

        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_advance_epoch_evm(
            ctx: &mut _, topic: String, target: $crate::lyquor_primitives::Address,
        ) -> LyquidResult<bool> {
            let target = $crate::runtime::oracle::oracle_target_evm_from_address(target)?;
            let call = $crate::runtime::oracle::SrcWrapper::new(topic.as_str()).advance_epoch(&mut ctx, target)?;
            if let Some(call) = call {
                $crate::runtime::lyquor_api::submit_call(call, false)?;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        #[$crate::method::instance(export = eth)]
        fn __lyquor_oracle_advance_epoch_lvm(
            ctx: &mut _, topic: String, target: $crate::lyquor_primitives::Address,
        ) -> LyquidResult<bool> {
            let target = $crate::runtime::oracle::oracle_target_lvm_from_address(ctx.lyquid_id, target)?;
            let call = $crate::runtime::oracle::SrcWrapper::new(topic.as_str()).advance_epoch(&mut ctx, target)?;
            if let Some(call) = call {
                $crate::runtime::lyquor_api::submit_call(call, false)?;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        #[$crate::method::instance(group = oracle::internal)]
        fn __lyquor_oracle_sync_targets(ctx: &mut _) -> LyquidResult<bool> {
            use $crate::runtime::oracle::OracleSrcStateContext as _;
            ctx.instance_internal_state_mut().sync_known_oracle_targets();
            Ok(true)
        }

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
            let topic_key = $crate::lyquor_primitives::oracle::topic_from_dispatch_group(topic.as_str());
            // Epoch-advance must be topic-level (`group == topic`), no group suffixes.
            if topic_key != topic.as_str() {
                return Err($crate::LyquidError::InputCert);
            }
            if $crate::lyquor_primitives::decode_by_fields!(
                wrapped.input_raw.as_ref(),
                config_delta: $crate::runtime::oracle::OracleConfigDeltaWire
            )
            .is_none()
            {
                return Err($crate::LyquidError::InputCert);
            }
            let params = $crate::lyquor_primitives::CallParams {
                // Canonicalize epoch params and let signature verification enforce exact binding.
                origin: $crate::lyquor_primitives::Address::ZERO,
                caller: $crate::lyquor_primitives::Address::ZERO,
                group: topic_key.to_string(),
                method: "__lyquor_oracle_on_epoch_advance".into(),
                input: wrapped.input_raw,
                abi: $crate::lyquor_primitives::InputABI::Lyquor,
            };
            if !ctx
                .network
                .__internal
                .oracle_dest(topic_key)
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
