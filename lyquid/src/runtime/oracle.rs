use super::StateAccessor;
use super::prelude::*;
pub use lyquor_primitives::oracle::{OracleCert, OracleHeader, OracleServiceTarget, OracleTarget, SignerID};
use lyquor_primitives::oracle::{OracleConfig as OracleConfigWire, OracleSigner, ValidatePreimage, eth};
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
/// - The `params` field carries the call to be sequenced, whose validation is done by `validate()`.
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
    pub fn verify(
        &self, lyquid_id: LyquidID, group: &str, proposer: NodeID, init: Bytes, nonce: HashBytes, oracle: &OracleSrc,
        seen: &mut HashSet<NodeID>,
    ) -> LyquidResult<bool> {
        if !seen.insert(self.from) {
            return Ok(false);
        }
        let signer = match oracle.committee.get(&self.from) {
            Some(s) => s,
            None => return Ok(false),
        };
        let key = signer.get_verifying_key(Cipher::Ed25519);
        ProposePreimage {
            lyquid_id,
            topic: oracle.topic.into(),
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

fn random_cert_nonce() -> Option<HashBytes> {
    let bytes = lyquor_api::random_bytes(32).ok()?;
    let hash = Hash::from_slice(&bytes).ok()?;
    Some(hash.into())
}

#[derive(Copy, Clone, Serialize, Deserialize)]
struct Signer {
    id: SignerID,
    key_lvm: [u8; 32], // ed25519 native key
    key_evm: Address,  // Secp256k1 signer's address
}

impl Signer {
    /// Return the key/address that is used for verification.
    fn get_verifying_key(&self, cipher: Cipher) -> Bytes {
        match cipher {
            Cipher::Ed25519 => Bytes::copy_from_slice(&self.key_lvm),
            Cipher::Secp256k1 => Bytes::copy_from_slice(self.key_evm.as_ref()),
        }
    }

    /// Get the wire format for a platform, determined by `cipher`.
    fn to_wire(&self, cipher: Cipher) -> OracleSigner {
        OracleSigner {
            id: self.id,
            key: self.get_verifying_key(cipher),
        }
    }
}

/// Per-topic network state for the source (certified call generation) chain.
pub struct OracleSrc {
    topic: &'static str,
    committee: HashMap<NodeID, Signer>,
    threshold: u16,
    /// Next SignerID to be assigned to a new node.
    ///
    /// This 32-bit counter keeps increasing and only wraps around to 0 when it hits 2^32. This
    /// guarantees that practically all nodes are given a unique 32-bit identifier, which shortens
    /// the [OracleCert] size and also makes it pubkey-agnostic. The destination chain keeps the
    /// pubkey/address for the committee, so that we can avoid repeating the pubkey by using such
    /// an identifer.
    next_signer_id: SignerID,
    /// Digest of the oracle's configuration (committee and threshold) for LVM target.
    config_hash_lvm: Hash,
    /// Digest of the oracle's configuration (committee and threshold) for EVM target.
    config_hash_evm: Hash,
    // TODO: record config deltas so [OracleCert] does not need to carry a full [OracleConfigWire]
    // every time when there is a change to the configuration.
}

impl OracleSrc {
    fn get_oracle_config_wire(&self, cipher: Cipher) -> OracleConfigWire {
        let mut committee: Vec<_> = self.committee.iter().map(|(_, s)| s.to_wire(cipher)).collect();
        // The canonical representation of a committee set is sorted by nodes' IDs.
        committee.sort_by_key(|s| s.id);
        OracleConfigWire {
            committee,
            threshold: self.threshold,
        }
    }

    fn update_config(&mut self) {
        // TODO: use a Merkle tree based approach so calculating new config hash (root hash)
        // doesn't have to serialize the entire config.
        self.config_hash_lvm = self.get_oracle_config_wire(Cipher::Ed25519).to_hash();
        self.config_hash_evm = eth::OracleConfig::from(self.get_oracle_config_wire(Cipher::Secp256k1)).to_hash();
    }

    pub fn new(topic: &'static str) -> Self {
        Self {
            topic,
            committee: new_hashmap(),
            threshold: 0,
            next_signer_id: 0,
            config_hash_lvm: Hash::from_bytes([0; 32]),
            config_hash_evm: Hash::from_bytes([0; 32]),
        }
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&mut self, id: NodeID) -> bool {
        let key_lvm = id.0;
        let key_evm = lyquor_api::get_ed25519_address(key_lvm)
            .ok()
            .flatten()
            .unwrap_or(Address::ZERO);
        let sid = self.next_signer_id;
        self.next_signer_id = self.next_signer_id.wrapping_add(1);
        let signer = Signer {
            id: sid,
            key_lvm,
            key_evm,
        };
        if self.committee.insert(id, signer).is_some() {
            return false;
        }
        self.update_config();
        true
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node(&mut self, id: &NodeID) -> bool {
        if self.committee.remove(id).is_none() {
            return false;
        }
        self.update_config();
        true
    }

    /// Get the committee size.
    pub fn len(&self) -> usize {
        self.committee.len()
    }

    /// Get the list of nodes in the committee.
    pub fn get_committee(&self) -> Vec<NodeID> {
        self.committee.keys().cloned().collect()
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold(&mut self, new_thres: u16) {
        if new_thres == self.threshold {
            return;
        }
        self.threshold = new_thres;
        self.update_config();
    }

    /// Get threshold of the committee.
    pub fn get_threshold(&self) -> u16 {
        return self.threshold
    }

    fn certify_with_nonce_group(
        &self, ctx: &impl OracleCertifyContext, params: CertifiedCallParams, extra: Bytes, group: String,
        nonce_fn: impl FnOnce() -> Option<HashBytes>,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 ||
            self.committee.len() > u16::MAX as usize ||
            self.committee.len() < self.threshold as usize
        {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "OracleSrc: invalid oracle configuration committee={}, threshold={}.",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }

        let (config_hash, abi) = match params.target.target {
            OracleServiceTarget::EVM { .. } => (self.config_hash_evm, InputABI::Eth),
            OracleServiceTarget::LVM(_) => (self.config_hash_lvm, InputABI::Lyquor),
        };
        // Populate epoch from instance state and derive a nonce per call.
        let nonce =
            nonce_fn().ok_or_else(|| LyquidError::LyquidRuntime("OracleSrc: failed to generate nonce.".into()))?;
        let epoch: u32 = 0; // TODO: use the cached epoch from instance state.
        let header = OracleHeader {
            proposer: ctx.get_node_id(),
            target: params.target,
            config_hash: config_hash.into(),
            epoch,
            nonce,
        };

        // The network fn call to be certified.
        let mut params = CallParams {
            origin: params.origin,
            caller: ctx.get_lyquid_id().into(),
            group,
            method: params.method,
            input: params.input,
            abi,
        };

        let yay = ValidatePreimage {
            header,
            params: params.clone(),
            approval: true,
        };

        let nay = ValidatePreimage {
            header,
            params: params.clone(),
            approval: false,
        };

        let (yay_msg, nay_msg) = match header.target.target {
            OracleServiceTarget::EVM { .. } => (
                eth::ValidatePreimage::try_from(yay).unwrap().to_preimage(),
                eth::ValidatePreimage::try_from(nay).unwrap().to_preimage(),
            ),
            OracleServiceTarget::LVM(_) => (yay.to_preimage(), nay.to_preimage()),
        };

        let cert: Option<OracleCert> = lyquor_api::universal_procedural_call(
            ctx.get_lyquid_id(),
            Some(format!("oracle::single_phase::{}", params.group)),
            "validate".into(),
            encode_by_fields!(msg: ValidateRequest = ValidateRequest {
                header,
                params: params.clone(),
                extra,
            }),
            Some(
                encode_by_fields!(
                    // Use oracle macro expected field "callee" for callee list and pass verification context.
                    callee: Vec<NodeID> = self.get_committee(),
                    header: OracleHeader = header,
                    yay_msg: Bytes = yay_msg.into(),
                    nay_msg: Bytes = nay_msg.into()
                )
                .into(),
            ),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

        Ok(cert.map(move |cert| {
            params.input = encode_by_fields!(cert: OracleCert = cert, input_raw: Bytes = params.input).into();
            params
        }))
    }

    fn certify_with_nonce(
        &self, ctx: &impl OracleCertifyContext, params: CertifiedCallParams, extra: Bytes,
        group_suffix: Option<&'static str>, nonce_fn: impl FnOnce() -> Option<HashBytes>,
    ) -> LyquidResult<Option<CallParams>> {
        let mut group: String = self.topic.into();
        if let Some(suffix) = group_suffix {
            use std::fmt::Write;
            write!(group, "::{suffix}")
                .map_err(|_| LyquidError::LyquidRuntime("OracleSrc: failed to write buffer.".into()))?;
        }
        self.certify_with_nonce_group(ctx, params, extra, group, nonce_fn)
    }

    /// Generate a self-certified call bundle under the oracle topic to be sequenced by the target
    /// network (sequence backend).
    pub fn certify(
        &self, ctx: &impl OracleCertifyContext, params: CertifiedCallParams, extra: Bytes,
        group_suffix: Option<&'static str>,
    ) -> LyquidResult<Option<CallParams>> {
        self.certify_with_nonce(ctx, params, extra, group_suffix, random_cert_nonce)
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
    pub fn propose_and_certify(
        &self, ctx: &impl OracleCertifyContext, init: Bytes, group_suffix: Option<&'static str>,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 ||
            self.committee.len() > u16::MAX as usize ||
            self.committee.len() < self.threshold as usize
        {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "OraclSrc: invalid oracle configuration: committee={}, threshold={}.",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }

        let lyquid = ctx.get_lyquid_id();
        let nonce = Hash::from_slice(&lyquor_api::random_bytes(32)?)
            .map_err(|_| LyquidError::LyquidRuntime("OracleSrc: failed to obtain proposal nonce.".into()))?
            .into();
        let mut group: String = self.topic.into();
        if let Some(suffix) = group_suffix {
            use std::fmt::Write;
            write!(group, "::{suffix}")
                .map_err(|_| LyquidError::LyquidRuntime("OracleSrc: failed to write buffer.".into()))?;
        }
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
                    callee: Vec<NodeID> = self.get_committee(),
                    init: Bytes = init.clone(),
                    nonce: HashBytes = nonce
                )
                .into(),
            ),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

        let mut validate_group: String = self.topic.into();
        match group_suffix {
            Some(suffix) => {
                use std::fmt::Write;
                write!(validate_group, "::two_phase::{suffix}")
                    .map_err(|_| LyquidError::LyquidRuntime("OracleSrc: failed to write buffer.".into()))?;
            }
            None => validate_group.push_str("::two_phase"),
        };
        match proposal {
            Some(p) => {
                let Proposal {
                    nonce: proposal_nonce,
                    inputs,
                    output,
                } = p;
                let cert_nonce = derive_two_phase_cert_nonce(proposal_nonce);
                self.certify_with_nonce_group(
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
        &self, header: &OracleHeader, params: &CallParams, expected_group: &str, from: NodeID, lyquid_id: LyquidID,
    ) -> bool {
        if from != header.proposer {
            return false;
        }
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
        let group_ok = match header.target.target {
            OracleServiceTarget::LVM(_) => params.group == expected_group,
            OracleServiceTarget::EVM { .. } => params
                .group
                .split("::")
                .next()
                .map(|topic| topic == self.topic)
                .unwrap_or(false),
        };
        if !group_ok {
            return false;
        }
        let hash = match header.target.target {
            OracleServiceTarget::LVM(_) => self.config_hash_lvm,
            OracleServiceTarget::EVM { .. } => self.config_hash_evm,
        };
        // Verify if the configuration in the proposal is consistent with the network state.
        if hash != *header.config_hash {
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

    pub fn __pre_validation_two_phase(&self, header: &OracleHeader, extra: &Bytes) -> bool {
        let payload = match lyquor_primitives::decode_by_fields!(
            extra,
            init: Bytes,
            nonce: HashBytes,
            inputs: Vec<ProposalInput>
        ) {
            Some(v) => v,
            None => return false,
        };
        derive_two_phase_cert_nonce(payload.nonce) == header.nonce
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
            topic: self.topic.into(),
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

    collected: HashSet<NodeID>,
    yea_sigs: Vec<(SignerID, Bytes)>,
    yea: u16,
    nay: u16,
    result: Option<Option<OracleCert>>,
}

/// UPC cache state for propose phase aggregation.
pub struct ProposalAggregation {
    init: Bytes,
    nonce: HashBytes,
    collected: HashSet<NodeID>,
    inputs: Vec<ProposalInput>,
    output: Option<Option<Proposal>>,
}

impl ProposalAggregation {
    pub fn new(init: Bytes, nonce: HashBytes) -> Self {
        Self {
            init,
            nonce,
            collected: new_hashset(),
            inputs: Vec::new(),
            output: None,
        }
    }

    pub fn add_response(
        &mut self, node: NodeID, resp: ProposeResponse, oracle: &OracleSrc,
        agg: fn(ProposalAggregationContext) -> LyquidResult<Option<CertifiedCallParams>>, lyquid_id: LyquidID,
        group: &str, proposer: NodeID,
    ) -> Option<Option<Proposal>> {
        // A node can only respond once.
        if self.output.is_some() || !self.collected.insert(node) {
            return self.output.clone();
        }

        let signer = oracle.committee.get(&node)?;
        let key = signer.get_verifying_key(Cipher::Ed25519);

        let preimage = ProposePreimage {
            lyquid_id,
            topic: oracle.topic.into(),
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

        // Let the LDK user's compute logic decide when there is enough of inputs.
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
        } else if oracle.committee.len() + self.inputs.len() < oracle.threshold as usize + self.collected.len() {
            self.output = Some(None);
        }

        self.output.clone()
    }
}

impl ValidateAggregation {
    pub fn new(header: OracleHeader, yea_msg: Bytes, nay_msg: Bytes) -> Self {
        Self {
            header,
            yea_msg,
            nay_msg,
            collected: new_hashset(),
            yea_sigs: Vec::new(),
            yea: 0,
            nay: 0,
            result: None,
        }
    }

    pub fn add_response(
        &mut self, node: NodeID, resp: ValidateResponse, oracle: &OracleSrc,
    ) -> Option<Option<OracleCert>> {
        // A node can only vote once.
        if self.result.is_some() || !self.collected.insert(node) {
            return self.result.clone();
        }

        let signer = oracle.committee.get(&node)?;
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

        if ok {
            match resp.approval {
                true => {
                    self.yea_sigs.push((signer.id, resp.sig.clone()));
                    self.yea += 1
                }
                false => self.nay += 1,
            }
        }

        crate::println!("yea = {}, thres = {}", self.yea, oracle.threshold);
        if self.yea >= oracle.threshold {
            // Canonicalize cert signer order so verifier can do O(n) monotonic checks.
            let mut yea_sigs = self.yea_sigs.clone();
            yea_sigs.sort_by_key(|(id, _)| *id);
            let (signers, signatures): (Vec<_>, Vec<_>) = yea_sigs.into_iter().unzip();
            self.result = Some(Some(OracleCert {
                header: self.header,
                // TODO: right now we just force every OracleCert to carry the current
                // configuration, even if it's the same. We should consult the destination
                // sequence backend (like we will do for epoch number) as a heuristic to avoid
                // carying the configuration when there is no change. Moreover, this `Option`
                // type should be replaced by the "delta" update approach.
                new_config: Some(oracle.get_oracle_config_wire(cipher)),
                signers,
                signatures,
            }))
        } else if oracle.committee.len() + (self.yea as usize) < (oracle.threshold as usize) + self.collected.len() {
            // Early failure: impossible to reach threshold with remaining nodes.
            self.result = Some(None)
        }
        self.result.clone()
    }
}

// TODO: use delta to update [`OracleConfigDest`] incrementally (instead of replacing it entirely).
// Mirrors `eth/src/lib/oracle.sol::_verifyOracleCert` for the LVM destination path.
fn verify_oracle_cert(
    oc: &OracleCert, params: CallParams, config: &OracleConfigDest, config_hash: &Hash,
) -> Result<Option<OracleConfigDest>, ()> {
    let mut config = config;
    let mut new_config = None;
    match &oc.new_config {
        Some(cfg) => {
            let hash: HashBytes = cfg.to_hash().into();
            if hash != oc.header.config_hash {
                // Config mismatch.
                return Err(());
            }
            new_config = Some(OracleConfigDest::from_wire(cfg));
            config = new_config.as_ref().unwrap();
        }
        None => {
            if &*oc.header.config_hash != config_hash {
                // Config mismatch.
                return Err(());
            }
        }
    }

    if oc.signers.len() != oc.signatures.len() {
        // Malformed certificate.
        return Err(());
    }

    if oc.signers.len() < config.threshold as usize {
        // Threshold not met.
        return Err(());
    }

    let cipher = oc.header.target.cipher();
    let msg: Bytes = ValidatePreimage {
        header: oc.header.clone(),
        params,
        approval: true,
    }
    .to_preimage()
    .into();

    let threshold = config.threshold as usize;
    let mut prev_id: Option<SignerID> = None;
    for (id, sig) in oc
        .signers
        .iter()
        .take(threshold)
        .zip(oc.signatures.iter().take(threshold))
    {
        if prev_id.map(|p| *id <= p).unwrap_or(false) {
            // Non-canonical signer set: unsorted or duplicate.
            return Err(());
        }
        prev_id = Some(*id);
        let verified = config
            .committee
            .get(id)
            .map(|key| {
                super::lyquor_api::verify(msg.clone(), cipher, sig.clone(), Bytes::copy_from_slice(key))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if !verified {
            return Err(());
        }
    }
    Ok(new_config)
}

/// Oracle configuration used by the destination.
struct OracleConfigDest {
    committee: HashMap<SignerID, Vec<u8>>,
    threshold: u16,
}

impl Default for OracleConfigDest {
    fn default() -> Self {
        Self {
            committee: new_hashmap(),
            threshold: 0,
        }
    }
}

impl OracleConfigDest {
    fn from_wire(oc: &OracleConfigWire) -> Self {
        let mut committee = new_hashmap();
        for signer in oc.committee.iter() {
            committee.insert(signer.id, signer.key.to_vec());
        }
        Self {
            committee,
            threshold: oc.threshold,
        }
    }
}

/// Per-topic network state for the destination (certified call execution) chain.
pub struct OracleDest {
    // The following states are used for certificate verification.
    // Active oracle config for the topic.
    config: OracleConfigDest,
    // Hash of _config for the topic.
    config_hash: HashBytes,
    // The following variables are used to ensure a certified call is at most invoked once.
    // Epoch number.
    epoch: u32,
    used_nonce: HashSet<Hash>,
}

impl Default for OracleDest {
    fn default() -> Self {
        Self {
            config: OracleConfigDest::default(),
            config_hash: [0; 32].into(),
            epoch: 0,
            used_nonce: new_hashset(),
        }
    }
}

/// Network state for the destination (call execution) chain.
impl OracleDest {
    /// Max nonce set size per epoch.
    const MAX_NONCE_PER_EPOCH: usize = 1_000_000;
    /// Min nonce set size for epoch advancement.
    const MIN_NONCE_NEXT_EPOCH: usize = Self::MAX_NONCE_PER_EPOCH * 9 / 10;

    pub fn get_epoch(&self) -> u32 {
        self.epoch
    }

    pub fn get_config_hash(&self) -> &HashBytes {
        &self.config_hash
    }

    pub fn signer_node_id(&self, id: SignerID) -> Option<NodeID> {
        let key = self.config.committee.get(&id)?;
        let key: [u8; 32] = key.as_slice().try_into().ok()?;
        Some(NodeID::from(key))
    }

    fn update_config(&mut self, config: OracleConfigDest, config_hash: HashBytes) -> bool {
        if config.threshold == 0 ||
            config.committee.len() > u16::MAX as usize ||
            config.committee.len() < config.threshold as usize
        {
            // Invalid config.
            return false;
        }
        self.config = config;
        self.config_hash = config_hash;
        true
    }

    /// Record a nonce in the given epoch. Returns false if invalid.
    fn record_nonce(&mut self, epoch: u32, nonce: Hash) -> bool {
        if epoch < self.epoch {
            // Stale epoch.
            return false;
        }

        // Enter a new epoch if higher.
        if epoch > self.epoch {
            if self.used_nonce.len() < Self::MIN_NONCE_NEXT_EPOCH {
                // Epoch advanced too early.
                return false;
            }
            self.epoch = epoch;
            self.used_nonce.clear();
        }

        if self.used_nonce.len() >= Self::MAX_NONCE_PER_EPOCH {
            // Epoch full.
            return false;
        }

        // Mark the nonce as used.
        self.used_nonce.insert(nonce)
        // false if Nonce is used.
    }

    pub fn verify(&mut self, me: LyquidID, params: lyquor_primitives::CallParams, oc: &OracleCert) -> bool {
        // TODO: Should rollback any changes made to self if the OracleCert can't pass
        // verification.
        // Mirrors eth/src/lib/oracle.sol::verify for the LVM destination path.

        // Ensure this certificate belongs to the active sequence backend.
        let backend = match lyquor_api::sequence_backend_id() {
            Ok(id) => id,
            Err(_) => return false,
        };
        if oc.header.target.seq_id != backend {
            return false;
        }

        // Ensure this certificate targets this Lyquid (LVM destination path only).
        // The EVM destination path checks `ethContract == address(this)` in oracle.sol.
        match &oc.header.target.target {
            OracleServiceTarget::LVM(id) => {
                if *id != me {
                    // Target mismatch (possible Lyquid-level replay attempt).
                    return false;
                }
            }
            _ => return false,
        }

        // Verify certificate signatures/config hash against the signed preimage.
        let new_config = match verify_oracle_cert(oc, params, &self.config, &self.config_hash) {
            Ok(cfg) => cfg,
            Err(_) => {
                // Invalid call certificate.
                return false;
            }
        };

        // Apply piggybacked config update (if any) before nonce recording.
        if let Some(config) = new_config {
            // This certificate also piggybacks a config update (that's signed
            // together with the call payload, and therefore has also been
            // validated). Let's first update the config because it is used for
            // this call and future calls, until a later update.
            if !self.update_config(config, oc.header.config_hash.clone()) {
                return false;
            }
        }

        // Record nonce to prevent replay.
        self.record_nonce(oc.header.epoch, oc.header.nonce.clone().into())
    }
}

/// Contexts that implement this trait support calling [`OracleSrc::certify`].
pub trait OracleCertifyContext: crate::runtime::internal::sealed::Sealed {
    fn get_lyquid_id(&self) -> LyquidID;
    fn get_node_id(&self) -> NodeID;
}

impl<S: StateAccessor, I: StateAccessor> OracleCertifyContext for crate::runtime::InstanceContextImpl<S, I> {
    fn get_lyquid_id(&self) -> LyquidID {
        return self.lyquid_id;
    }
    fn get_node_id(&self) -> NodeID {
        return self.node_id;
    }
}

impl<S: StateAccessor, I: StateAccessor> OracleCertifyContext for crate::runtime::ImmutableInstanceContextImpl<S, I> {
    fn get_lyquid_id(&self) -> LyquidID {
        return self.lyquid_id;
    }
    fn get_node_id(&self) -> NodeID {
        return self.node_id;
    }
}

impl<S: StateAccessor, I: StateAccessor> OracleCertifyContext for crate::runtime::upc::RequestContextImpl<S, I> {
    fn get_lyquid_id(&self) -> LyquidID {
        return self.lyquid_id;
    }
    fn get_node_id(&self) -> NodeID {
        return self.node_id;
    }
}

pub struct ProposalAggregationContext<'a> {
    pub init: &'a [u8],
    pub inputs: &'a [ProposalInput],
    pub lyquid_id: LyquidID,
}
