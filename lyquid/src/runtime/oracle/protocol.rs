//! Oracle certification protocol flows (single-phase / two-phase / epoch-advance).

use super::source::{OracleSrc, Signer};
use super::*;
use lyquor_primitives::oracle::{OracleConfigDelta as OracleConfigDeltaWire, ValidatePreimage, eth};
use lyquor_primitives::{Address, Bytes, CallParams, Cipher, Hash, HashBytes, InputABI};
use serde::{Deserialize, Serialize};

/// Necessary info filled by the user for a certified call to be sequenced.
///
/// # Contract With LDK User
///
/// For both single-phase and two-phase flows, these are the user-policy fields and should be
/// validated by the Lyquid developer in `validate()` (and usually in `aggregate()` for two-phase):
///
/// - `target` is acceptable for this call.
/// - `origin`, `method`, and `input` satisfy the application's intended semantics.
///
/// The framework then handles protocol-level checks and aggregation, so a valid `OracleCert`
/// represents a call approved by threshold-majority validation under the active oracle config.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CertifiedCallParams {
    pub origin: Address,
    pub method: String,
    pub input: Bytes,
    pub target: OracleTarget,
}

/// UPC message sent to each validator for proposal validation.
///
/// The validator (signer) will check `header` to see if it's consistent with its oracle
/// configuration as of the given network state version, and then run the user-defined `validate`
/// function to sign for its approval/disapproval.
///
/// - The `header` field carries the call's setup, whose validation is automated by this LDK.
/// - The `params` field carries the call to be sequenced, whose validation is done by
///   `validate()`.
/// - The `extra` field carries the supplementary information given by the proposer to each
/// validator for its local consideration during `validate()`. This data will NOT be signed or
/// contained in [ValidateResponse]. Like `params`, its validity is not verified when passed to
/// `validate()`.
///
/// The entire flow done by `validate()` looks like this:
///
/// ```
/// [header] --------------------------LDK checked-------------------.--> signed [header] & [params]
/// [params] ---[custom validation]\____validate()---> true/false ---/
/// [extra]  ---[custom validation]/
/// ```
///
/// By making a [ValidateResponse], the validator gives its attestation for both the `header` and
/// the `params` that will be sequenced, implicitly with the help of the extra information. A
/// signature will be automatically signed, and the validator will respond to the proposer with
/// `validate()`'s result (true/false).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidateRequest {
    /// Metadata for the setup of this call to be signed and sequenced.
    pub header: OracleHeader,
    /// Call parameters to be signed and sequenced.
    pub params: CallParams,
    /// Supplementary data not to be signed or sequenced.
    pub extra: Bytes,
}

/// UPC message responded from each validator after validation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidateResponse {
    /// If the validator approves (`true`) or disapproves (`false`) the proposal.
    pub approval: bool,
    /// [ValidatePreimage] signature.
    pub sig: Bytes,
}

/// UPC message sent to solicit each node's input value for proposal aggregation.
///
/// Each node that participates in this input collection phase will derive its input from the
/// given initial value (`init`) by the proposer, followed by signing the initial value together
/// with its input.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposeRequest {
    /// Initial arguments passed to each node for deriving their input.
    pub init: Bytes,
    /// Proposal nonce to bind a specific first-phase round.
    pub nonce: HashBytes,
}

/// UPC message responded from each node for its input for aggregation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposeResponse {
    /// The produced input value.
    pub input: Bytes,
    /// [ProposePreimage] signature.
    pub sig: Bytes,
}

/// Input proposed by a node.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProposalInput {
    pub from: NodeID,
    pub input: Bytes,
    pub sig: Bytes,
}

impl ProposalInput {
    fn verify(
        &self, lyquid_id: LyquidID, topic: &str, group: &str, proposer: NodeID, init: Bytes, nonce: HashBytes,
        config: &OracleConfig, seen: &mut HashSet<NodeID>,
    ) -> LyquidResult<bool> {
        if !seen.insert(self.from) {
            return Ok(false);
        }
        let signer = match config.committee.get(&self.from) {
            Some(s) => s,
            None => return Ok(false),
        };
        let key = signer.get_verifying_key(Cipher::Ed25519);
        ProposePreimage {
            lyquid_id,
            topic: topic.into(),
            group: group.into(),
            proposer,
            init,
            nonce,
            input: self.input.clone(),
        }
        .verify(self.sig.clone(), key)
    }
}

/// Preimage to be signed during the propose phase. This is private because it is only required
/// during off-chain computation.
#[derive(Serialize, Deserialize)]
struct ProposePreimage {
    lyquid_id: LyquidID,
    topic: String,
    group: String,
    proposer: NodeID,
    init: Bytes,
    nonce: HashBytes,
    input: Bytes,
}

impl ProposePreimage {
    const PREFIX: &'static [u8] = b"lyquor_propose_preimage_v1\0";

    fn to_preimage(&self) -> Vec<u8> {
        lyquor_primitives::encode_object_with_prefix(Self::PREFIX, self)
    }

    fn verify(&self, sig: Bytes, pk: Bytes) -> LyquidResult<bool> {
        let m = self.to_preimage();
        lyquor_api::verify(m.into(), Cipher::Ed25519, sig, pk)
    }
}

/// Proposal used in validation (second) phase.
///
/// During validation, each node checks the validity of inputs and whether
/// `output == aggregate(inputs)`.
/// The `output` field is used to form the `params` field of [ValidateResponse].
/// The `inputs` field is given to the `extra` field of [ValidateResponse], used by
/// LDK-generated validation code (see [super::syntax]).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proposal {
    nonce: HashBytes,
    inputs: Vec<ProposalInput>,
    output: CertifiedCallParams,
}

/// Derive second-phase certificate nonce from first-phase proposal nonce.
fn derive_two_phase_cert_nonce(proposal_nonce: HashBytes) -> HashBytes {
    blake3::hash(&<[u8; 32]>::from(proposal_nonce)).into()
}

#[inline]
fn is_epoch_validate_group(topic: &str, group: &str) -> bool {
    group
        .strip_prefix(topic)
        .and_then(|suffix| suffix.strip_prefix("::"))
        .is_some_and(|suffix| suffix == ORACLE_EPOCH_VALIDATE_GROUP_SUFFIX)
}

impl<'a> SrcWrapper<'a> {
    fn certify_with_nonce<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
        &self, ctx: &mut crate::runtime::InstanceContextImpl<S, I>, params: CertifiedCallParams, extra: Bytes,
        group: String, nonce_fn: impl FnOnce() -> Option<HashBytes>,
    ) -> LyquidResult<Option<CallParams>> {
        let abi = match params.target.target {
            OracleServiceTarget::EVM { .. } => InputABI::Eth,
            OracleServiceTarget::LVM(_) => InputABI::Lyquor,
        };
        let lyquid_id = ctx.lyquid_id;
        let mut call_params = CallParams {
            origin: params.origin,
            caller: lyquid_id.into(),
            group,
            method: params.method,
            input: params.input,
            abi,
        };
        let source = ctx
            .instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .target_state_mut(params.target.target);
        let config = source.current_config().clone();
        if !config.is_valid() {
            return Ok(None);
        }
        let config_hash = *source.current_config_hash();
        let callee = config.committee.keys().cloned().collect::<Vec<_>>();

        // Use source-side epoch and derive a nonce per call.
        let nonce =
            nonce_fn().ok_or_else(|| LyquidError::LyquidRuntime("SrcWrapper: failed to generate nonce.".into()))?;
        let header = OracleHeader {
            proposer: ctx.node_id,
            target: params.target,
            config_hash: config_hash.into(),
            epoch: config.epoch,
            nonce,
        };

        let cert = self.collect_cert(
            lyquid_id,
            call_params.group.as_str(),
            header,
            call_params.clone(),
            extra,
            callee,
            config,
        )?;

        Ok(cert.map(move |cert| {
            call_params.input = encode_by_fields!(cert: OracleCert = cert, input_raw: Bytes = call_params.input).into();
            call_params
        }))
    }

    fn collect_cert(
        &self, lyquid_id: LyquidID, validate_group: &str, header: OracleHeader, params: CallParams, extra: Bytes,
        callee: Vec<NodeID>, vote_config: OracleConfig,
    ) -> LyquidResult<Option<OracleCert>> {
        let yea = ValidatePreimage {
            header,
            params: params.clone(),
            approval: true,
        };

        let nay = ValidatePreimage {
            header,
            params: params.clone(),
            approval: false,
        };

        let (yea_msg, nay_msg) = match header.target.target {
            OracleServiceTarget::EVM { .. } => (
                eth::ValidatePreimage::try_from(yea).unwrap().to_preimage(),
                eth::ValidatePreimage::try_from(nay).unwrap().to_preimage(),
            ),
            OracleServiceTarget::LVM(_) => (yea.to_preimage(), nay.to_preimage()),
        };

        lyquor_api::universal_procedural_call(
            lyquid_id,
            Some(format!("oracle::single_phase::{}", validate_group)),
            "validate".into(),
            encode_by_fields!(msg: ValidateRequest = ValidateRequest {
                header,
                params: params.clone(),
                extra,
            }),
            Some(
                encode_by_fields!(
                    // Use oracle macro expected field "callee" for callee list and pass verification context.
                    callee: Vec<NodeID> = callee,
                    header: OracleHeader = header,
                    yea_msg: Bytes = yea_msg.into(),
                    nay_msg: Bytes = nay_msg.into(),
                    vote_config: OracleConfig = vote_config
                )
                .into(),
            ),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))
    }

    /// Generate a self-certified call bundle under the oracle topic to be sequenced by the target
    /// network (sequence backend).
    pub fn certify<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
        &self, ctx: &mut crate::runtime::InstanceContextImpl<S, I>, params: CertifiedCallParams, extra: Bytes,
        group_suffix: Option<&'static str>,
    ) -> LyquidResult<Option<CallParams>> {
        let group = lyquor_primitives::oracle::group_with_topic_suffix(self.topic(), group_suffix);
        self.certify_with_nonce(ctx, params, extra, group, super::random_cert_nonce)
    }

    /// Generate a self-certified call bundle under the oracle topic to be sequenced by the target
    /// network (sequence backend). The proposal is first aggregated from inputs collected from nodes,
    /// and then certified through the committee.
    ///
    /// This is a two-phase process.
    ///
    /// 1. **Propose**: The proposer (the node who initiates the whole process) uses a UPC with an
    ///    initial value to solicit some nodes for their proposed inputs respectively. The
    ///    user-defined `aggregate(...)` function deterministically aggregates the inputs (a list
    ///    of [ProposalInput]) into an output ([CertifiedCallParams]), and also decides when it is
    ///    ok to stop waiting for more inputs.
    ///
    ///                            ------> <Node A>
    ///                           /        ...
    /// <proposer>---init----------------> <Node B>
    ///                           \------> <Node C>
    ///
    ///              ---input_A----------< <Node A>
    ///             /                      ...
    /// <proposer> <----input_B----------< <Node B>
    ///             \---input_C----------< <Node C>
    ///
    /// <proposer>: output = aggregate({input_A, input_B, input_C})
    ///
    /// 2. **Validate**: The proposer then uses a second UPC (through [Self::certify]) to form a
    ///    certified call to be sequenced by the sequence backend.
    ///
    /// Use [Self::certify] directly if the initial aggregation phase is not needed (e.g., to
    /// certify network state that is consistent across all nodes from one chain to another).
    ///
    pub fn propose_and_certify<
        S: crate::runtime::internal::StateAccessor,
        I: crate::runtime::internal::StateAccessor,
    >(
        &self, ctx: &mut crate::runtime::InstanceContextImpl<S, I>, target: OracleServiceTarget, init: Bytes,
        group_suffix: Option<&'static str>,
    ) -> LyquidResult<Option<CallParams>> {
        let lyquid = ctx.lyquid_id;
        let source = ctx
            .instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .target_state_mut(target);
        let config = source.current_config().clone();
        if !config.is_valid() {
            return Ok(None);
        }
        let callee = config.committee.keys().cloned().collect::<Vec<_>>();
        let nonce = Hash::from_slice(&lyquor_api::random_bytes(32)?)
            .map_err(|_| LyquidError::LyquidRuntime("SrcWrapper: failed to obtain proposal nonce.".into()))?
            .into();
        let group = lyquor_primitives::oracle::group_with_topic_suffix(self.topic(), group_suffix);
        let proposal: Option<Proposal> = lyquor_api::universal_procedural_call(
            lyquid,
            Some(format!("oracle::two_phase::{group}")),
            "propose".into(),
            encode_by_fields!(msg: ProposeRequest = ProposeRequest {
                init: init.clone(),
                nonce,
            }),
            Some(
                encode_by_fields!(
                    callee: Vec<NodeID> = callee,
                    init: Bytes = init.clone(),
                    nonce: HashBytes = nonce,
                    vote_config: OracleConfig = config
                )
                .into(),
            ),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

        let mut validate_group = lyquor_primitives::oracle::group_with_topic_suffix(self.topic(), Some("two_phase"));
        if let Some(suffix) = group_suffix {
            use std::fmt::Write;
            write!(validate_group, "::{suffix}")
                .map_err(|_| LyquidError::LyquidRuntime("SrcWrapper: failed to write buffer.".into()))?;
        }
        match proposal {
            Some(p) => {
                let Proposal {
                    nonce: proposal_nonce,
                    inputs,
                    output,
                } = p;
                let cert_nonce = derive_two_phase_cert_nonce(proposal_nonce);
                self.certify_with_nonce(
                    ctx,
                    output,
                    encode_by_fields!(
                        init: Bytes = init,
                        nonce: HashBytes = proposal_nonce,
                        inputs: Vec<ProposalInput> = inputs
                    )
                    .into(),
                    validate_group,
                    || Some(cert_nonce),
                )
            }
            None => Ok(None),
        }
    }

    pub fn __pre_validation(
        &self, oracle: &mut OracleSrc, header: &OracleHeader, params: &CallParams, expected_group: &str, from: NodeID,
        lyquid_id: LyquidID,
    ) -> bool {
        if from != header.proposer {
            return false;
        }
        let state = oracle.target_state_mut(header.target.target);
        let hash_ok = if is_epoch_advance_params(self.topic(), params) {
            if !is_epoch_validate_group(self.topic(), expected_group) {
                return false;
            }
            state.pre_validate_epoch_advance(header.epoch, &header.config_hash)
        } else {
            let abi_ok = match header.target.target {
                OracleServiceTarget::LVM(_) => params.abi == InputABI::Lyquor,
                OracleServiceTarget::EVM { .. } => params.abi == InputABI::Eth,
            };
            if !abi_ok {
                return false;
            }
            if params.caller != Address::from(lyquid_id) {
                return false;
            }
            if params.group != expected_group {
                return false;
            }
            if header.epoch != state.current_config().epoch {
                return false;
            }
            *state.current_config_hash() == *header.config_hash
        };
        // Verify if the configuration in the proposal is consistent with the local state.
        if !hash_ok {
            return false;
        }

        match header.target.target {
            OracleServiceTarget::LVM(_) => true,
            OracleServiceTarget::EVM { eth_contract, .. } => lyquor_api::eth_contract()
                .ok()
                .flatten()
                .is_some_and(|contract| eth_contract == contract),
        }
    }

    /// Decode and verify two-phase proposal payload and signatures against current oracle state.
    pub fn __pre_validation_two_phase(
        &self, oracle: &mut OracleSrc, header: &OracleHeader, extra: &Bytes, lyquid_id: LyquidID, group: &str,
        proposer: NodeID,
    ) -> LyquidResult<Option<(Bytes, HashBytes, Vec<ProposalInput>)>> {
        let payload = match lyquor_primitives::decode_by_fields!(
            extra,
            init: Bytes,
            nonce: HashBytes,
            inputs: Vec<ProposalInput>
        ) {
            Some(v) => v,
            None => return Ok(None),
        };
        if derive_two_phase_cert_nonce(payload.nonce) != header.nonce {
            return Ok(None);
        }
        let config = &oracle.target_state_mut(header.target.target).current_config();
        let mut seen = new_hashset();
        for input in &payload.inputs {
            if !input.verify(
                lyquid_id,
                self.topic(),
                group,
                proposer,
                payload.init.clone(),
                payload.nonce,
                config,
                &mut seen,
            )? {
                return Ok(None);
            }
        }
        Ok(Some((payload.init, payload.nonce, payload.inputs)))
    }

    pub fn __post_validation(
        &self, header: OracleHeader, params: CallParams, approval: bool,
    ) -> LyquidResult<ValidateResponse> {
        let preimage = ValidatePreimage {
            header,
            params,
            approval,
        };

        let (cipher, m) = match header.target.target {
            OracleServiceTarget::EVM { .. } => (
                Cipher::Secp256k1,
                eth::ValidatePreimage::try_from(preimage).unwrap().to_preimage(),
            ),
            OracleServiceTarget::LVM(_) => (Cipher::Ed25519, preimage.to_preimage()),
        };

        let sig = lyquor_api::sign(m.into(), cipher)?;
        Ok(ValidateResponse { approval, sig })
    }

    pub fn __post_propose(
        &self, lyquid_id: LyquidID, group: &str, proposer: NodeID, init: Bytes, nonce: HashBytes, input: Bytes,
    ) -> LyquidResult<ProposeResponse> {
        let preimage = ProposePreimage {
            lyquid_id,
            topic: self.topic().to_string(),
            group: group.into(),
            proposer,
            init,
            nonce,
            input: input.clone(),
        };
        let sig = lyquor_api::sign(preimage.to_preimage().into(), Cipher::Ed25519)?;
        Ok(ProposeResponse { input, sig })
    }

    /// Generate an epoch-advance certificate that carries all current staged changes to the
    /// target chain.
    pub fn advance_epoch<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
        &self, ctx: &mut crate::runtime::InstanceContextImpl<S, I>, target: OracleTarget,
    ) -> LyquidResult<Option<CallParams>> {
        let validate_group =
            lyquor_primitives::oracle::group_with_topic_suffix(self.topic(), Some(ORACLE_EPOCH_VALIDATE_GROUP_SUFFIX));
        let source = ctx
            .instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .target_state_mut(target.target);

        let (epoch, config, delta, config_hash) = match source.staging_delta() {
            Some(d) => d,
            None => return Ok(None),
        };
        let config = config.clone();
        let callee = config.committee.keys().cloned().collect::<Vec<_>>();

        let nonce = super::random_cert_nonce()
            .ok_or_else(|| LyquidError::LyquidRuntime("SrcWrapper: failed to generate nonce.".into()))?;
        let topic = self.topic().to_string();
        let lvm_target = matches!(&target.target, OracleServiceTarget::LVM(_));
        let header = OracleHeader {
            proposer: ctx.node_id,
            target,
            config_hash: config_hash.into(),
            epoch,
            nonce,
        };
        let mut params = CallParams {
            origin: Address::ZERO,
            caller: Address::ZERO,
            // Epoch advance is topic-level. `validate_group` only selects the dedicated
            // single-phase route used for voting.
            group: topic.clone(),
            method: LVM_ORACLE_ON_EPOCH_ADVANCE_METHOD.into(),
            input: encode_by_fields!(config_delta: OracleConfigDeltaWire = delta).into(),
            abi: InputABI::Lyquor,
        };
        let cert = self.collect_cert(
            ctx.lyquid_id,
            validate_group.as_str(),
            header,
            params.clone(),
            Bytes::new(),
            callee,
            config,
        )?;
        Ok(cert.map(move |cert| {
            let payload: Bytes =
                encode_by_fields!(cert: OracleCert = cert, input_raw: Bytes = params.input.clone()).into();
            if lvm_target {
                CallParams {
                    origin: Address::ZERO,
                    caller: Address::ZERO,
                    group: "oracle::internal".into(),
                    method: LVM_ORACLE_ON_EPOCH_ADVANCE_METHOD.into(),
                    input: encode_by_fields!(topic: String = topic, payload: Bytes = payload).into(),
                    abi: InputABI::Lyquor,
                }
            } else {
                params.input = payload;
                params
            }
        }))
    }
}
/// UPC cache state for validate phase aggregation.
pub struct ValidateAggregation {
    header: OracleHeader,
    approved_msg: Bytes,
    nay_msg: Bytes,
    vote_committee: HashMap<NodeID, Signer>,
    vote_threshold: u16,

    collected: HashSet<NodeID>,
    approved_sigs: Vec<(SignerID, Bytes)>,
    approved: u16,
    result: Option<Option<OracleCert>>,
}

/// UPC cache state for propose phase aggregation.
pub struct ProposalAggregation {
    vote_committee: HashMap<NodeID, Signer>,
    vote_threshold: u16,
    init: Bytes,
    nonce: HashBytes,
    collected: HashSet<NodeID>,
    inputs: Vec<ProposalInput>,
    output: Option<Option<Proposal>>,
}

impl ProposalAggregation {
    pub fn new(init: Bytes, nonce: HashBytes, vote_config: OracleConfig) -> Self {
        let vote_committee = vote_config.committee;
        let vote_threshold = vote_config.threshold;
        Self {
            vote_committee,
            vote_threshold,
            init,
            nonce,
            collected: new_hashset(),
            inputs: Vec::new(),
            output: None,
        }
    }

    pub fn add_response(
        &mut self, node: NodeID, resp: ProposeResponse,
        agg: fn(ProposalAggregationContext) -> LyquidResult<Option<CertifiedCallParams>>, lyquid_id: LyquidID,
        topic: &str, group: &str, proposer: NodeID,
    ) -> Option<Option<Proposal>> {
        if self.output.is_some() {
            return self.output.clone();
        }
        let signer = match self.vote_committee.get(&node) {
            Some(signer) => signer,
            None => return self.output.clone(),
        };
        // A committee node can only respond once.
        if !self.collected.insert(node) {
            return self.output.clone();
        }

        if self.vote_threshold == 0 || self.vote_committee.len() < self.vote_threshold as usize {
            self.output = Some(None);
            return self.output.clone();
        }

        let key = signer.get_verifying_key(Cipher::Ed25519);

        let preimage = ProposePreimage {
            lyquid_id,
            topic: topic.to_string(),
            group: group.into(),
            proposer,
            init: self.init.clone(),
            nonce: self.nonce,
            input: resp.input.clone(),
        };
        let ok = preimage.verify(resp.sig.clone(), key).ok().unwrap_or(false);

        if ok {
            self.inputs.push(ProposalInput {
                from: node,
                input: resp.input,
                sig: resp.sig,
            });
        }

        // Let the LDK user's aggregation logic decide when enough inputs are collected.
        // We ignore the error from agg(), treating it as "not ready" or "failure" which implies not setting the output yet.
        // Or should we panic? Usually runtime errors in user logic should bubble up, but here we are in a state update
        // triggered by response. Since return type is Option<Option<Proposal>>, we can't easily propagate error.
        // For now let's treat error as None (no output).
        if let Ok(Some(output)) = agg(ProposalAggregationContext {
            init: &self.init,
            inputs: &self.inputs,
            lyquid_id,
        }) {
            self.output = Some(Some(Proposal {
                nonce: self.nonce,
                inputs: self.inputs.clone(),
                output,
            }));
        } else if self.vote_committee.len() + self.inputs.len() < self.vote_threshold as usize + self.collected.len() {
            self.output = Some(None);
        }

        self.output.clone()
    }
}

impl ValidateAggregation {
    pub fn new(header: OracleHeader, approved_msg: Bytes, nay_msg: Bytes, vote_config: OracleConfig) -> Self {
        let vote_committee = vote_config.committee;
        let vote_threshold = vote_config.threshold;
        Self {
            header,
            approved_msg,
            nay_msg,
            vote_committee,
            vote_threshold,
            collected: new_hashset(),
            approved_sigs: Vec::new(),
            approved: 0,
            result: None,
        }
    }

    pub fn add_response(&mut self, node: NodeID, resp: ValidateResponse) -> Option<Option<OracleCert>> {
        if self.result.is_some() {
            return self.result.clone();
        }
        let signer = match self.vote_committee.get(&node).copied() {
            Some(signer) => signer,
            None => return self.result.clone(),
        };
        // A committee node can only vote once.
        if !self.collected.insert(node) {
            return self.result.clone();
        }

        if self.vote_threshold == 0 || self.vote_committee.len() < self.vote_threshold as usize {
            self.result = Some(None);
            return self.result.clone();
        }
        let threshold = self.vote_threshold;
        let committee_len = self.vote_committee.len();
        let cipher = self.header.target.cipher();
        let key = signer.get_verifying_key(cipher);

        let ok = super::lyquor_api::verify(
            if resp.approval {
                &self.approved_msg
            } else {
                &self.nay_msg
            }
            .clone(),
            cipher,
            resp.sig.clone(),
            key,
        )
        .ok()
        .unwrap_or(false);

        if ok && resp.approval {
            self.approved_sigs.push((signer.id, resp.sig.clone()));
            self.approved += 1
        }

        if self.approved >= threshold {
            // Canonicalize cert signer order so verifier can do O(n) monotonic checks.
            let mut approved_sigs = self.approved_sigs.clone();
            approved_sigs.sort_by_key(|(id, _)| *id);
            let (signers, signatures): (Vec<_>, Vec<_>) = approved_sigs.into_iter().unzip();
            self.result = Some(Some(OracleCert {
                header: self.header,
                signers,
                signatures,
            }))
        } else if committee_len + (self.approved as usize) < (threshold as usize) + self.collected.len() {
            // Early failure: impossible to reach threshold with remaining nodes.
            self.result = Some(None)
        }
        self.result.clone()
    }
}
pub struct ProposalAggregationContext<'a> {
    pub init: &'a [u8],
    pub inputs: &'a [ProposalInput],
    pub lyquid_id: LyquidID,
}
