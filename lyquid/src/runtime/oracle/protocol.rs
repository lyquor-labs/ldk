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
fn two_phase_cert_nonce(proposal_nonce: HashBytes) -> HashBytes {
    blake3::hash(&<[u8; 32]>::from(proposal_nonce)).into()
}

fn group_from_chunks(prefix: &str, suffix: &[Option<&str>]) -> String {
    let mut group = prefix.to_string();
    for s in suffix {
        if let Some(s) = s {
            group.push_str("::");
            group.push_str(s);
        }
    }
    group
}

fn random_cert_nonce() -> Option<HashBytes> {
    let bytes = lyquor_api::random_bytes(32).ok()?;
    let hash = Hash::from_slice(&bytes).ok()?;
    Some(hash.into())
}

fn validate_phase(
    lyquid_id: LyquidID, proposer: NodeID, group_suffix: &str, target: OracleTarget, epoch: u32,
    config_hash: HashBytes, mut params: CallParams, extra: Bytes, config: OracleConfig,
    nonce_fn: impl FnOnce() -> Option<HashBytes>, timeout_ms: Option<u64>,
) -> LyquidResult<Option<CallParams>> {
    let nonce = nonce_fn().ok_or_else(|| LyquidError::LyquidRuntime("NEAT: failed to generate nonce.".into()))?;
    let callee = config.committee.keys().cloned().collect::<Vec<_>>();
    let input_raw = params.input.clone();
    let header = OracleHeader {
        proposer,
        target,
        config_hash,
        epoch,
        nonce,
    };
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
        Some(group_from_chunks("oracle", &[Some("single_phase"), Some(group_suffix)])),
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
                config: OracleConfig = config
            )
            .into(),
        ),
        timeout_ms,
    )
    .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))
    .map(|cert: Option<OracleCert>| {
        cert.map(move |cert| {
            params.input = encode_by_fields!(cert: OracleCert = cert, input_raw: Bytes = input_raw).into();
            params
        })
    })
}

fn certify<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
    ctx: &mut crate::runtime::InstanceContextImpl<S, I>, topic: &str, params: CertifiedCallParams, extra: Bytes,
    group_suffix: Option<&'static str>, timeout_ms: Option<u64>,
) -> LyquidResult<Option<CallParams>> {
    let lyquid = ctx.lyquid_id;
    let Some(source) = crate::runtime::internal::builtin_network_state()
        .oracle_src(topic)
        .and_then(|oracle| oracle.source_state(params.target))
    else {
        return Ok(None);
    };
    let config = source.current_config().clone();
    if !config.is_valid() {
        return Ok(None);
    }
    let group = group_from_chunks(topic, &[group_suffix]);
    let call_params = CallParams {
        origin: params.origin,
        caller: lyquid.into(),
        group: group.clone(),
        method: params.method,
        input: params.input,
        abi: match params.target.target {
            OracleServiceTarget::EVM { .. } => InputABI::Eth,
            OracleServiceTarget::LVM(_) => InputABI::Lyquor,
        },
    };
    validate_phase(
        lyquid,
        ctx.node_id,
        &group,
        params.target,
        config.epoch,
        source.current_config_hash().into(),
        call_params,
        extra,
        config,
        random_cert_nonce,
        timeout_ms,
    )
}

fn propose_and_certify<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
    ctx: &mut crate::runtime::InstanceContextImpl<S, I>, topic: &str, target: OracleTarget, init: Bytes,
    group_suffix: Option<&'static str>, timeout_ms: Option<u64>,
) -> LyquidResult<Option<CallParams>> {
    let lyquid = ctx.lyquid_id;
    let Some(source) = crate::runtime::internal::builtin_network_state()
        .oracle_src(topic)
        .and_then(|oracle| oracle.source_state(target))
    else {
        return Ok(None);
    };
    let config = source.current_config().clone();
    if !config.is_valid() {
        return Ok(None);
    }
    let callee = config.committee.keys().cloned().collect::<Vec<_>>();
    let nonce = Hash::from_slice(&lyquor_api::random_bytes(32)?)
        .map_err(|_| LyquidError::LyquidRuntime("NEAT: failed to obtain proposal nonce.".into()))?
        .into();
    let proposal: Option<Proposal> = lyquor_api::universal_procedural_call(
        lyquid,
        Some(group_from_chunks(
            "oracle",
            &[Some("two_phase"), Some(topic), group_suffix],
        )),
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
                vote_config: OracleConfig = config.clone()
            )
            .into(),
        ),
        timeout_ms,
    )
    .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

    let Proposal {
        nonce: proposal_nonce,
        inputs,
        output,
    } = match proposal {
        Some(p) => p,
        None => return Ok(None),
    };
    let cert_nonce = two_phase_cert_nonce(proposal_nonce);
    let group = group_from_chunks(topic, &[Some("two_phase"), group_suffix]);
    let call_params = CallParams {
        origin: output.origin,
        caller: lyquid.into(),
        group: group.clone(),
        method: output.method,
        input: output.input,
        abi: match output.target.target {
            OracleServiceTarget::EVM { .. } => InputABI::Eth,
            OracleServiceTarget::LVM(_) => InputABI::Lyquor,
        },
    };
    validate_phase(
        lyquid,
        ctx.node_id,
        &group,
        output.target,
        config.epoch,
        source.current_config_hash().into(),
        call_params,
        encode_by_fields!(
            init: Bytes = init,
            nonce: HashBytes = proposal_nonce,
            inputs: Vec<ProposalInput> = inputs
        )
        .into(),
        config,
        || Some(cert_nonce),
        timeout_ms,
    )
}

/// Generate an epoch-advance certificate for the target chain.
///
/// The staged config delta may be empty, in which case this is an explicit epoch rollover without
/// reconfiguration.
fn advance_epoch<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
    ctx: &mut crate::runtime::InstanceContextImpl<S, I>, topic: &str, target: OracleTarget,
) -> LyquidResult<Option<CallParams>> {
    let Some(source) = crate::runtime::internal::builtin_network_state().oracle_src(topic) else {
        return Ok(None);
    };
    let (epoch, config, delta, config_hash, change_count) = match source.propose_advance_epoch(target) {
        Some(d) => d,
        None => return Ok(None),
    };
    let config = config.clone();
    let group = group_from_chunks(topic, &[Some(EPOCH_GROUP_SUFFIX)]);
    let params = CallParams {
        origin: Address::ZERO,
        caller: Address::from(ctx.lyquid_id),
        group: "oracle::internal".to_string(),
        method: ADVANCE_EPOCH_METHOD.into(),
        input: encode_by_fields!(
            topic: String = topic.to_string(),
            config_delta: OracleConfigDeltaWire = delta,
            change_count: u32 = change_count
        )
        .into(),
        abi: InputABI::Lyquor,
    };
    validate_phase(
        ctx.lyquid_id,
        ctx.node_id,
        &group,
        target,
        epoch,
        config_hash.into(),
        params,
        Bytes::new(),
        config,
        random_cert_nonce,
        None,
    )
}

fn finalize_epoch<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
    ctx: &mut crate::runtime::InstanceContextImpl<S, I>, topic: &str, target: OracleTarget,
) -> LyquidResult<Option<CallParams>> {
    // This is the target-canonical state that source wants to adopt.
    let Some(target_info) = lyquor_api::fetch_oracle_info(topic.to_string(), target, false)? else {
        return Ok(None);
    };
    let source = OracleTarget {
        seq_id: lyquor_api::sequence_backend_id()?,
        target: OracleServiceTarget::LVM(ctx.lyquid_id),
    };
    let Some(source_state) = crate::runtime::internal::builtin_network_state()
        .oracle_src(topic)
        .and_then(|oracle| oracle.source_state(source))
    else {
        return Ok(None);
    };
    let (source_epoch, source_config, source_hash) = if target == source {
        match source_state.materialize_prefix(target_info.change_count) {
            Some((config, _)) if config.is_valid() => {
                let hash = config.to_hash(source.cipher());
                (config.epoch, config, hash)
            }
            _ => return Ok(None),
        }
    } else {
        let config = source_state.current_config().clone();
        if !config.is_valid() {
            return Ok(None);
        }
        (config.epoch, config, source_state.current_config_hash())
    };

    // `finalize_epoch(...)` is certified under the source target and adopts the observed
    // target-canonical state in its payload.
    let source_target = oracle_target_from_address(Address::from(ctx.lyquid_id), false)?;
    let group = group_from_chunks(topic, &[Some(EPOCH_GROUP_SUFFIX)]);
    let params = CallParams {
        origin: Address::ZERO,
        caller: Address::from(ctx.lyquid_id),
        group: group.clone(),
        method: FINALIZE_EPOCH_METHOD.into(),
        input: encode_by_fields!(
            target: OracleTarget = target,
            target_info: OracleEpochInfo = target_info
        )
        .into(),
        abi: InputABI::Lyquor,
    };
    validate_phase(
        ctx.lyquid_id,
        ctx.node_id,
        &group,
        source_target,
        source_epoch,
        source_hash.into(),
        params,
        Bytes::new(),
        source_config,
        random_cert_nonce,
        None,
    )
}

impl<'a> StateVar<'a> {
    /// Generate a self-certified call bundle under the oracle topic to be sequenced by the target
    /// network (sequence backend).
    #[inline]
    pub fn certify<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
        &self, ctx: &mut crate::runtime::InstanceContextImpl<S, I>, params: CertifiedCallParams, extra: Bytes,
        group_suffix: Option<&'static str>, timeout_ms: Option<u64>,
    ) -> LyquidResult<Option<CallParams>> {
        certify(ctx, self.topic(), params, extra, group_suffix, timeout_ms)
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
    #[inline]
    pub fn propose_and_certify<
        S: crate::runtime::internal::StateAccessor,
        I: crate::runtime::internal::StateAccessor,
    >(
        &self, ctx: &mut crate::runtime::InstanceContextImpl<S, I>, target: OracleTarget, init: Bytes,
        group_suffix: Option<&'static str>, timeout_ms: Option<u64>,
    ) -> LyquidResult<Option<CallParams>> {
        propose_and_certify(ctx, self.topic(), target, init, group_suffix, timeout_ms)
    }

    /// Generate an epoch-advance certificate for the target chain, carrying the current staged
    /// delta when present or an explicit no-op rollover otherwise.
    #[inline]
    pub fn advance_epoch<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
        &self, ctx: &mut crate::runtime::InstanceContextImpl<S, I>, target: OracleTarget,
    ) -> LyquidResult<Option<CallParams>> {
        advance_epoch(ctx, self.topic(), target)
    }

    #[inline]
    pub fn finalize_epoch<S: crate::runtime::internal::StateAccessor, I: crate::runtime::internal::StateAccessor>(
        &self, ctx: &mut crate::runtime::InstanceContextImpl<S, I>, target: OracleTarget,
    ) -> LyquidResult<Option<CallParams>> {
        finalize_epoch(ctx, self.topic(), target)
    }

    pub fn __pre_validation(
        &self, oracle: &OracleSrc, header: &OracleHeader, params: &CallParams, group: &str, from: NodeID,
        lyquid_id: LyquidID,
    ) -> Option<bool> {
        if from != header.proposer {
            return None;
        }

        let is_epoch_vote = group == &group_from_chunks(self.topic(), &[Some(EPOCH_GROUP_SUFFIX)]);
        let is_advance_epoch = is_epoch_vote && params.method == ADVANCE_EPOCH_METHOD;
        let is_finalize_epoch = is_epoch_vote && params.method == FINALIZE_EPOCH_METHOD;
        if is_advance_epoch {
            if params.abi != lyquor_primitives::InputABI::Lyquor ||
                params.group != "oracle::internal" ||
                params.method != ADVANCE_EPOCH_METHOD ||
                params.origin != Address::ZERO ||
                params.caller != Address::from(lyquid_id)
            {
                return None;
            }
            let payload = match lyquor_primitives::decode_by_fields!(
                &params.input,
                topic: String,
                config_delta: OracleConfigDeltaWire,
                change_count: u32
            ) {
                Some(payload) => payload,
                None => return None,
            };
            if !oracle.validate_advance_epoch(
                header.target,
                payload.topic.as_str(),
                header.epoch,
                &header.config_hash,
                &payload.config_delta,
                payload.change_count,
            ) {
                return None;
            }
        } else if is_finalize_epoch {
            let payload = match lyquor_primitives::decode_by_fields!(
                &params.input,
                target: OracleTarget,
                target_info: OracleEpochInfo
            ) {
                Some(payload) => payload,
                None => return None,
            };
            if params.abi != lyquor_primitives::InputABI::Lyquor ||
                params.group != group ||
                params.method != FINALIZE_EPOCH_METHOD ||
                params.origin != Address::ZERO ||
                params.caller != Address::from(lyquid_id)
            {
                return None;
            }
            if header.target !=
                (OracleTarget {
                    seq_id: lyquor_api::sequence_backend_id().ok()?,
                    target: OracleServiceTarget::LVM(lyquid_id),
                })
            {
                return None;
            }
            if !oracle.validate_finalize_epoch(payload.target, &payload.target_info) {
                return None;
            }
        } else {
            let state = oracle.source_state(header.target)?;
            let abi_ok = match header.target.target {
                OracleServiceTarget::LVM(_) => params.abi == InputABI::Lyquor,
                OracleServiceTarget::EVM { .. } => params.abi == InputABI::Eth,
            };
            if !abi_ok ||
                params.group != group ||
                params.caller != Address::from(lyquid_id) ||
                header.epoch != state.current_config().epoch ||
                state.current_config_hash() != *header.config_hash
            {
                return None;
            }
        }

        match header.target.target {
            OracleServiceTarget::LVM(_) => true,
            OracleServiceTarget::EVM { eth_contract, .. } => lyquor_api::eth_contract()
                .ok()
                .flatten()
                .is_some_and(|contract| eth_contract == contract),
        }
        .then_some(is_epoch_vote)
    }

    /// Decode and verify two-phase proposal payload and signatures against current oracle state.
    pub fn __pre_validation_two_phase(
        &self, oracle: &OracleSrc, header: &OracleHeader, extra: &Bytes, lyquid_id: LyquidID, group: &str,
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
        if two_phase_cert_nonce(payload.nonce) != header.nonce {
            return Ok(None);
        }
        let Some(config) = oracle.source_state(header.target).map(|state| state.current_config()) else {
            return Ok(None);
        };
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
}

/// UPC cache state for validate phase aggregation.
pub struct ValidateAggregation {
    header: OracleHeader,
    yea_msg: Bytes,
    nay_msg: Bytes,
    committee: HashMap<NodeID, Signer>,
    threshold: u16,

    collected: HashSet<NodeID>,
    approved_sigs: Vec<(SignerID, Bytes)>,
    approved: u16,
    result: Option<Option<OracleCert>>,
}

/// UPC cache state for propose phase aggregation.
pub struct ProposalAggregation {
    committee: HashMap<NodeID, Signer>,
    threshold: u16,
    init: Bytes,
    nonce: HashBytes,
    collected: HashSet<NodeID>,
    inputs: Vec<ProposalInput>,
    output: Option<Option<Proposal>>,
}

impl ProposalAggregation {
    pub fn new(init: Bytes, nonce: HashBytes, config: OracleConfig) -> Self {
        let committee = config.committee;
        let threshold = config.threshold;
        Self {
            committee,
            threshold,
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
        let signer = match self.committee.get(&node) {
            Some(signer) => signer,
            None => return self.output.clone(),
        };
        // A committee node can only respond once.
        if !self.collected.insert(node) {
            return self.output.clone();
        }

        if self.threshold == 0 || self.committee.len() < self.threshold as usize {
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
        } else if self.committee.len() + self.inputs.len() < self.threshold as usize + self.collected.len() {
            self.output = Some(None);
        }

        self.output.clone()
    }
}

impl ValidateAggregation {
    pub fn new(header: OracleHeader, yea_msg: Bytes, nay_msg: Bytes, vote_config: OracleConfig) -> Self {
        let committee = vote_config.committee;
        let threshold = vote_config.threshold;
        Self {
            header,
            yea_msg,
            nay_msg,
            committee,
            threshold,
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
        let signer = match self.committee.get(&node).copied() {
            Some(signer) => signer,
            None => return self.result.clone(),
        };
        // A committee node can only vote once.
        if !self.collected.insert(node) {
            return self.result.clone();
        }

        if self.threshold == 0 || self.committee.len() < self.threshold as usize {
            self.result = Some(None);
            return self.result.clone();
        }

        let cipher = self.header.target.cipher();
        let key = signer.get_verifying_key(cipher);

        let ok = super::lyquor_api::verify(
            if resp.approval { &self.yea_msg } else { &self.nay_msg }.clone(),
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

        if self.approved >= self.threshold {
            // Canonicalize cert signer order so verifier can do O(n) monotonic checks.
            let mut approved_sigs = self.approved_sigs.clone();
            approved_sigs.sort_by_key(|(id, _)| *id);
            let (signers, signatures): (Vec<_>, Vec<_>) = approved_sigs.into_iter().unzip();
            self.result = Some(Some(OracleCert {
                header: self.header,
                signers,
                signatures,
            }))
        } else if self.committee.len() + (self.approved as usize) < (self.threshold as usize) + self.collected.len() {
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
