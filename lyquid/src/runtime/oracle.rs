use super::{
    Deserialize, HashMap, HashSet, LyquidError, LyquidID, LyquidResult, NodeID, Serialize, StateAccessor, lyquor_api,
    new_hashmap, new_hashset,
};
pub use lyquor_primitives::oracle::{OracleCert, OracleHeader, OracleTarget, SignerID};
use lyquor_primitives::oracle::{OracleConfig as OracleConfigWire, OracleSigner, ValidatePreimage, eth};
use lyquor_primitives::{Address, Bytes, CallParams, Cipher, Hash, HashBytes, InputABI};

/// Necessary info required for a certified call to be sequenced.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CertifiedCallParams {
    pub origin: Address,
    pub method: String,
    pub input: Bytes,
    pub target: OracleTarget,
}

/// UPC message sent to each validator for proposal validation.
///
/// The validator (signer) will check config hash to see if it's consistent with its oracle
/// configuration state as of the given network state version, and then run the user-defined
/// `validate` function to sign for its approval/disapproval.
///
/// The `params` field carries the part that needs to be sequenced.
/// The `extra` field carries the supplementary information given to each validator for its local
/// validation consideration, as needed by the LDK user.
///
/// By making a [ValidateResponse], the validator gives its attestation for both the header and the
/// params that will be sequenced, and also implicitly with the help of the extra information. A
/// signature will be automatically signed, and the validator will respond to the proposer with
/// `validate()`'s result (true/false).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidateRequest {
    /// Metadata for the Oracle's setup.
    pub header: OracleHeader,
    /// Certified call parameters to be sequenced.
    pub params: CallParams,
    /// Supplementary data interpreted by the validate() function, which do NOT need to be sequenced.
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
/// Each node that participates in this input collection phase will derive the its input from the
/// given initial value (`init`) by the proposer, followed by signing the initial value together
/// with its input.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposeRequest {
    /// Initial arguments passed to each node for deriving their input.
    pub init: Bytes,
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
    pub fn verify(&self, init: Bytes, oracle: &OracleSrc) -> LyquidResult<bool> {
        let signer = match oracle.committee.get(&self.from) {
            Some(s) => s,
            None => return Ok(false),
        };
        let key = signer.get_verifying_key(Cipher::Ed25519);
        ProposePreimage {
            init,
            input: self.input.clone(),
        }
        .verify(self.sig.clone(), key)
    }
}

/// Preimage to be signed during the Propose phase. This is private because it is only required
/// during off-chain computation.
#[derive(Serialize, Deserialize)]
struct ProposePreimage {
    /// The initial value given by the proposer, signed together to avoid equivocation by the
    // proposer.
    init: Bytes,
    /// The input value responded by the solicited node.
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
/// During validation, each node will check the validity of inputs, and whether output = aggregate(inputs).
/// The `output` field will be used to form the `params` field of [ValidateResponse].
/// The `inputs` field will be given to the `extra` field of [ValidateResponse] to be used by the
/// LDK-generated validation code (see [super::syntax]).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proposal {
    inputs: Vec<ProposalInput>,
    output: CertifiedCallParams,
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
    /// the OracleCert size and also makes it pubkey-agnostic. The destination chain will keep the
    /// pubkey/address for the committee, so that we can avoid repeating the pubkey by using such
    /// an identifer.
    next_signer_id: SignerID,
    /// Digest of the oracle's configuration (committee and threshold) for LVM target.
    config_hash_lvm: Hash,
    /// Digest of the oracle's configuration (committee and threshold) for EVM target.
    config_hash_evm: Hash,
    // TODO: recored config deltas so OracleCert does not need to carry a full OracleConfigWire
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

    /// Generate a self-certified call bundle under the oracle topic to be sequenced by the target
    /// network (sequence backend).
    pub fn certify(
        &self, ctx: &impl OracleCertifyContext, params: CertifiedCallParams, extra: Bytes,
        group_suffix: Option<&'static str>,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 ||
            self.committee.len() > u16::MAX as usize ||
            self.committee.len() < self.threshold as usize
        {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "Invalid oracle configuration: committee.len()={}, threshold={}.",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }

        let (config_hash, abi) = match params.target {
            OracleTarget::EVM(_) => (self.config_hash_evm, InputABI::Eth),
            OracleTarget::LVM(_) => (self.config_hash_lvm, InputABI::Lyquor),
        };
        // Populate epoch from instance state and derive a nonce per call.
        let nonce = Hash::from_slice(&lyquor_api::random_bytes(32)?)
            .map_err(|_| LyquidError::LyquidRuntime("OracleSrc: failed to obtain random nonce.".into()))?
            .into();
        let epoch: u32 = 0; // TODO: use the cached epoch from instance state.
        let header = OracleHeader {
            proposer: ctx.get_node_id(),
            target: params.target,
            config_hash: config_hash.into(),
            epoch,
            nonce,
        };

        let mut group: String = self.topic.into();
        if let Some(suffix) = group_suffix {
            use std::fmt::Write;
            write!(group, "::{suffix}")
                .map_err(|_| LyquidError::LyquidRuntime("OracleSrc: failed to write buffer.".into()))?;
        }
        // The network fn call to be certified.
        let mut params = CallParams {
            origin: params.origin,
            caller: params.origin,
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

        let (yay_msg, nay_msg) = match header.target {
            OracleTarget::EVM(_) => (
                eth::ValidatePreimage::try_from(yay).unwrap().to_preimage(),
                eth::ValidatePreimage::try_from(nay).unwrap().to_preimage(),
            ),
            OracleTarget::LVM(_) => (yay.to_preimage(), nay.to_preimage()),
        };

        let cert: Option<OracleCert> = lyquor_api::universal_procedural_call(
            ctx.get_lyquid_id(),
            Some(format!("oracle::single_phase::{}", params.group)),
            "validate".into(),
            lyquor_primitives::encode_by_fields!(msg: ValidateRequest = ValidateRequest {
                header,
                params: params.clone(),
                extra,
            }),
            Some(
                lyquor_primitives::encode_by_fields!(
                    // Use oracle macro expected field "callee" for callee list and pass verification context.
                    callee: Vec<NodeID> = self.committee.keys().cloned().collect(),
                    header: OracleHeader = header,
                    yay_msg: Bytes = yay_msg.into(),
                    nay_msg: Bytes = nay_msg.into()
                )
                .into(),
            ),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

        Ok(cert.map(move |cert| {
            params.input = crate::encode_by_fields!(cert: OracleCert = cert, input_raw: Bytes = params.input).into();
            params
        }))
    }

    /// Generate a self-certified call bundle under the oracle topic to be sequenced by the target
    /// network (sequence backend). The proposal is first aggregated from the inputs of some nodes,
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
    /// 2. **Validate**: The proposer then uses a second UPC (through [Self::ceritfy]) to form a
    ///    certified call to be sequenced by the sequence backend.
    ///
    /// Use [Self::certify] directly if the initial aggregation phase is not needed (e.g., to just
    /// ceritify some network state which is the consistent across all nodes from one chain to
    /// another).
    ///
    pub fn propose_and_certify(
        &self, ctx: &impl OracleCertifyContext, init: Bytes, group_suffix: Option<&'static str>,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 ||
            self.committee.len() > u16::MAX as usize ||
            self.committee.len() < self.threshold as usize
        {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "Invalid oracle configuration: committee.len()={}, threshold={}.",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }

        let lyquid = ctx.get_lyquid_id();
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
            lyquor_primitives::encode_by_fields!(msg: ProposeRequest = ProposeRequest {
                init: init.clone(),
            }),
            Some(
                lyquor_primitives::encode_by_fields!(
                    callee: Vec<NodeID> = self.committee.keys().cloned().collect(),
                    init: Bytes = init.clone()
                )
                .into(),
            ),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

        match proposal {
            Some(p) => self.certify(
                ctx,
                p.output,
                lyquor_primitives::encode_by_fields!(
                    init: Bytes = init,
                    inputs: Vec<ProposalInput> = p.inputs
                )
                .into(),
                Some("two_phase"),
            ),
            None => Ok(None),
        }
    }

    pub fn __pre_validation(&self, header: &OracleHeader) -> bool {
        let hash = match header.target {
            OracleTarget::LVM(_) => self.config_hash_lvm,
            OracleTarget::EVM(_) => self.config_hash_evm,
        };
        // Verify if the configuration in the proposal is consistent with the network state.
        hash == *header.config_hash
    }

    pub fn __post_validation(
        &self, header: OracleHeader, params: CallParams, approval: bool,
    ) -> LyquidResult<ValidateResponse> {
        let preimage = ValidatePreimage {
            header,
            params,
            approval,
        };

        let (cipher, m) = match header.target {
            OracleTarget::EVM(_) => (
                Cipher::Secp256k1,
                eth::ValidatePreimage::try_from(preimage).unwrap().to_preimage(),
            ),
            OracleTarget::LVM(_) => (Cipher::Ed25519, preimage.to_preimage()),
        };

        let sig = lyquor_api::sign(m.into(), cipher)?;
        Ok(ValidateResponse { approval, sig })
    }

    pub fn __post_propose(&self, init: Bytes, input: Bytes) -> LyquidResult<ProposeResponse> {
        let preimage = ProposePreimage {
            init,
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

/// UPC cache state for propose phrase aggregation.
pub struct ProposalAggregation {
    init: Bytes,
    collected: HashSet<NodeID>,
    inputs: Vec<ProposalInput>,
    output: Option<Option<Proposal>>,
}

impl ProposalAggregation {
    pub fn new(init: Bytes) -> Self {
        Self {
            init,
            collected: new_hashset(),
            inputs: Vec::new(),
            output: None,
        }
    }

    pub fn add_response(
        &mut self, node: NodeID, resp: ProposeResponse, oracle: &OracleSrc,
        agg: fn(ProposalAggregationContext) -> LyquidResult<Option<CertifiedCallParams>>, lyquid_id: LyquidID,
    ) -> Option<Option<Proposal>> {
        // A node can only respond once.
        if self.output.is_some() || !self.collected.insert(node) {
            return self.output.clone();
        }

        let signer = oracle.committee.get(&node)?;
        let key = signer.get_verifying_key(Cipher::Ed25519);

        let preimage = ProposePreimage {
            init: self.init.clone(),
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
                inputs: self.inputs.clone(),
                output,
            }));
        } else if oracle.committee.len() - (self.collected.len() - self.inputs.len()) < oracle.threshold as usize {
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
            let mut signers = Vec::new();
            let mut signatures = Vec::new();
            for (id, sig) in self.yea_sigs.clone().into_iter() {
                signers.push(id);
                signatures.push(sig);
            }
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
        } else if oracle.committee.len() - (self.collected.len() - self.yea as usize) < oracle.threshold as usize {
            // Early failure: impossible to reach threshold with remaining nodes.
            self.result = Some(None)
        }
        self.result.clone()
    }
}

// TODO: use delta to update OracleConfigDest incrementally (instead of replacing it entirely).
fn verify_oracle_cert(
    oc: &OracleCert, msg: Bytes, config: &OracleConfigDest, config_hash: &Hash,
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

    for (id, sig) in oc
        .signers
        .iter()
        .zip(oc.signatures.iter().take(config.threshold as usize))
    {
        let key = match config.committee.get(id) {
            Some(k) => k.clone(),
            None => return Err(()),
        };

        if !super::lyquor_api::verify(msg.clone(), cipher, sig.clone(), Bytes::copy_from_slice(&key)).unwrap_or(false) {
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
    const MAX_NONCE_PER_EPOCH: usize = 1_000_000;

    pub fn get_epoch(&self) -> u32 {
        self.epoch
    }

    pub fn get_config_hash(&self) -> &HashBytes {
        &self.config_hash
    }

    fn update_config(&mut self, config: OracleConfigDest, config_hash: HashBytes) -> bool {
        if config.committee.is_empty() {
            // No signers.
            return false;
        }
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
            if self.used_nonce.len() < Self::MAX_NONCE_PER_EPOCH {
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

    pub fn verify(&mut self, me: LyquidID, params: lyquor_primitives::CallParams, oc: OracleCert) -> bool {
        // Ensure the certificate targets this Lyquid
        match oc.header.target {
            OracleTarget::LVM(id) => {
                if id != me {
                    // Target mismatch (possible Lyquid-level replay attempt).
                    return false;
                }
            }
            _ => return false,
        }

        // Ensure the preimage matches the signed digest.
        let msg = ValidatePreimage {
            header: oc.header,
            params,
            approval: true,
        }
        .to_preimage()
        .into();

        // Verify the validity of the OracleCert.
        let new_config = match verify_oracle_cert(&oc, msg, &self.config, &self.config_hash) {
            Ok(cfg) => cfg,
            Err(_) => {
                // Invalid call certificate.
                return false;
            }
        };

        if let Some(config) = new_config {
            // This certificate also piggybacks a config update (that's signed
            // together with the call payload, and therefore has also been
            // validated). Let's first update the config because it is used for
            // this call and future calls, until a later update.
            if !self.update_config(config, oc.header.config_hash) {
                return false;
            }
        }

        // Prevent the call from being used again.
        self.record_nonce(oc.header.epoch, oc.header.nonce.into())
    }
}

/// Contexts that impls this trait are those that support calling `OracleSrc::certify()`.
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
