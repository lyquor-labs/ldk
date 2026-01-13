use super::{Deserialize, LyquidError, LyquidID, LyquidResult, NodeID, Serialize, StateAccessor, lyquor_api, network};
pub use lyquor_primitives::oracle::{OracleCert, OracleHeader, OracleTarget};
use lyquor_primitives::oracle::{OracleConfig, OraclePreimage, OracleSigner, ProposePreimage, eth};
use lyquor_primitives::{Address, Bytes, CallParams, Cipher, Hash, HashBytes, InputABI};

/// Validate UPC message sent to each validator.
///
/// The validator (signer) will check config hash to see if it's consistent with its oracle state
/// as of the given network state version, and then run `validate`.
///
/// The `witness` field carries evidence from the proposal phase, typically containing
/// the set of signed inputs from committee members. This allows the validator to verify that the
/// proposed value was correctly aggregated from these inputs before signing its approval.
///
/// If validation succeeds, a signature will be
/// automatically signed, and the validator willrespond to the caller with `validate()`'s result (true/false).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidateRequest {
    pub header: OracleHeader,
    pub params: CallParams,
    /// Empty if there is no witness payload (no proposal step).
    pub witness: Bytes,
}

/// UPC message responded from each validator after validation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidateResponse {
    pub approval: bool,
    pub sig: Bytes,
}

/// Propose UPC message sent to each committee member to collect its input value.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposeRequest {
    pub header: OracleHeader,
    /// User-provided arguments (opaque bytes) for `propose(...)`.
    pub args: Bytes,
}

/// Propose UPC response from each committee member.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposeResponse {
    /// The produced input value (opaque bytes), to be aggregated by proposer.
    pub value: Bytes,
    /// Signature over `(header, args, value)`.
    pub sig: Bytes,
}

/// Collected evidence from a node in proposal phase.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProposeAttestation<T = Bytes> {
    pub from: NodeID,
    pub value: T,
    pub sig: Bytes,
}

/// Witness payload forwarded to phase `validate(...)` so validators can check the proposed
/// aggregation inputs.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposeWitness<T = Bytes> {
    pub header: OracleHeader,
    pub args: Bytes,
    pub attestations: Vec<ProposeAttestation<T>>,
}

impl<T: Serialize> ProposeAttestation<T> {
    pub fn verify(&self, header: OracleHeader, args: &Bytes, cipher: Cipher, pk: Bytes) -> LyquidResult<bool> {
        let value_bytes = lyquor_primitives::encode_object(&self.value);
        let preimage = ProposePreimage {
            header,
            args: args.clone(),
            value: value_bytes.into(),
        };

        let m = match header.target {
            OracleTarget::EVM(_) => eth::ProposePreimage::try_from(preimage).unwrap().to_preimage(),
            OracleTarget::LVM(_) => preimage.to_preimage(),
        };

        lyquor_api::verify(m.into(), cipher, self.sig.clone(), pk)
    }
}

/// A witness that has been cryptographically verified by the platform.
/// Contains only the inputs from authorized committee members with valid signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedWitness<T> {
    pub header: OracleHeader,
    pub args: Bytes,
    /// Only contains values whose signatures have been verified against the committee.
    pub values: Vec<T>,
}

/// Trait to allow automatic decoding and verification of oracle witnesses.
pub trait FromWitness: Sized {
    fn from_witness(b: Bytes, oracle: &OracleSrc, cipher: Cipher) -> LyquidResult<Self>;
}

impl FromWitness for Bytes {
    fn from_witness(b: Bytes, _oracle: &OracleSrc, _cipher: Cipher) -> LyquidResult<Self> {
        Ok(b)
    }
}

impl<T: Serialize + serde::de::DeserializeOwned> FromWitness for VerifiedWitness<T> {
    fn from_witness(b: Bytes, oracle: &OracleSrc, cipher: Cipher) -> LyquidResult<Self> {
        if b.is_empty() {
            return Ok(VerifiedWitness {
                header: OracleHeader {
                    proposer: NodeID::new([0; 32]),
                    target: OracleTarget::LVM(LyquidID::from_owner_nonce(&Address::ZERO, 0)),
                    config_hash: HashBytes::new([0; 32].into()),
                    epoch: 0,
                    nonce: HashBytes::new([0; 32].into()),
                },
                args: Bytes::new(),
                values: Vec::new(),
            });
        }
        let w: ProposeWitness<T> = lyquor_primitives::decode_object(&b).ok_or(LyquidError::LyquorInput)?;
        let mut verified_values = Vec::new();

        for att in w.attestations {
            let pk = oracle
                .pubkey_for_cipher(&att.from, cipher)
                .ok_or_else(|| LyquidError::OracleError(format!("Unknown node in witness: {}", att.from)))?;

            if !att.verify(w.header, &w.args, cipher, pk)? {
                return Err(LyquidError::OracleError(format!(
                    "Invalid signature in witness from node: {}",
                    att.from
                )));
            }
            verified_values.push(att.value);
        }

        Ok(VerifiedWitness {
            header: w.header,
            args: w.args,
            values: verified_values,
        })
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
struct Signer {
    id: NodeID,
    lvm: [u8; 32], // ed25519 native key
    evm: Address,  // Secp256k1 signer's address
}

impl Signer {
    /// Return the key/address that needs to be used for verification.
    fn get_verifying_key(&self, cipher: Cipher) -> Bytes {
        match cipher {
            Cipher::Ed25519 => Bytes::copy_from_slice(&self.lvm),
            Cipher::Secp256k1 => Bytes::copy_from_slice(self.evm.as_ref()),
        }
    }

    fn to_wire(&self, cipher: Cipher) -> OracleSigner {
        OracleSigner {
            id: self.id,
            key: self.get_verifying_key(cipher),
        }
    }
}

struct OracleConfigSrc {
    committee: network::Vec<Signer>,
    threshold: u16,
}

impl Default for OracleConfigSrc {
    fn default() -> Self {
        Self {
            committee: network::new_vec(),
            threshold: 0,
        }
    }
}

impl OracleConfigSrc {
    fn to_wire(&self, cipher: Cipher) -> OracleConfig {
        OracleConfig {
            committee: self.committee.iter().map(|s| s.to_wire(cipher)).collect(),
            threshold: self.threshold,
        }
    }
}

/// Network state for the source (call generation) chain.
pub struct OracleSrc {
    id: &'static str,
    threshold: u16,
    committee: network::HashMap<NodeID, Signer>,
    config: OracleConfigSrc,
    config_hash_lvm: Hash,
    config_hash_evm: Hash,
    // TODO: keep the incremental updates here since the old one so we don't have to carry the entire Config each time
}

impl OracleSrc {
    fn cipher_for_target(target: &OracleTarget) -> Cipher {
        match target {
            OracleTarget::EVM(_) => Cipher::Secp256k1,
            OracleTarget::LVM(_) => Cipher::Ed25519,
        }
    }

    pub fn pubkey_for_cipher(&self, node: &NodeID, cipher: Cipher) -> Option<Bytes> {
        self.committee.get(node).map(|s| s.get_verifying_key(cipher))
    }

    fn update_config(&mut self) {
        // Consolidate the current config into the wire format (that can be hashed or used as part of
        // the signed payload).
        self.config.committee.clear();
        for signer in self.committee.values() {
            self.config.committee.push(*signer);
        }
        self.config.committee.sort_by_key(|s| s.id);
        self.config.threshold = self.threshold;
        self.config_hash_lvm = self.config.to_wire(Cipher::Ed25519).to_hash();
        self.config_hash_evm = eth::OracleConfig::from(self.config.to_wire(Cipher::Secp256k1)).to_hash();
    }

    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            threshold: 0,
            committee: network::new_hashmap(),
            config: OracleConfigSrc::default(),
            config_hash_lvm: Hash::from_bytes([0; 32]),
            config_hash_evm: Hash::from_bytes([0; 32]),
        }
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&mut self, id: NodeID) -> bool {
        let lvm = id.0;
        let evm = lyquor_api::get_ed25519_address(lvm)
            .ok()
            .flatten()
            .unwrap_or(Address::ZERO);

        let signer = Signer { id, lvm, evm };
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

    /// Generate a certificate that testifies the validity of an oracle call to a target network
    /// (sequence backend).
    pub fn certify(
        &self, ctx: &impl OracleCertifyContext, origin: Address, method: String, input: Bytes, target: OracleTarget,
    ) -> LyquidResult<Option<CallParams>> {
        self.certify_with_witness(ctx, origin, method, input, target, Bytes::new())
    }

    /// Same as `certify`, but also forwards an opaque witness to validators.
    pub fn certify_with_witness(
        &self, ctx: &impl OracleCertifyContext, origin: Address, method: String, input: Bytes, target: OracleTarget,
        witness: Bytes,
    ) -> LyquidResult<Option<CallParams>> {
        let header = self.build_header(ctx, target)?;
        self.certify_with_header_and_witness(ctx, origin, method, input, header, witness)
    }

    fn certify_with_header_and_witness(
        &self, ctx: &impl OracleCertifyContext, origin: Address, method: String, input: Bytes, header: OracleHeader,
        witness: Bytes,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 ||
            self.committee.len() > u16::MAX as usize ||
            self.committee.len() < self.threshold as usize
        {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "Invalid OracleConfig(committee.len()={}, threshold={}).",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }

        let lyquid = ctx.get_lyquid_id();

        let abi = match header.target {
            OracleTarget::EVM(_) => InputABI::Eth,
            OracleTarget::LVM(_) => InputABI::Lyquor,
        };

        // The network fn call to be certified.
        let mut params = CallParams {
            origin,
            caller: origin,
            group: self.id.into(),
            method,
            input,
            abi,
        };

        let yay = OraclePreimage {
            header,
            params: params.clone(),
            approval: true,
        };

        let nay = OraclePreimage {
            header,
            params: params.clone(),
            approval: false,
        };

        let (yay_msg, nay_msg) = match header.target {
            OracleTarget::EVM(_) => (
                eth::OraclePreimage::try_from(yay).unwrap().to_preimage(),
                eth::OraclePreimage::try_from(nay).unwrap().to_preimage(),
            ),
            OracleTarget::LVM(_) => (yay.to_preimage(), nay.to_preimage()),
        };

        let cert: Option<OracleCert> = lyquor_api::universal_procedural_call(
            lyquid,
            Some(format!("oracle::committee::{}", self.id)),
            "validate".into(),
            lyquor_primitives::encode_by_fields!(msg: ValidateRequest = ValidateRequest {
                header,
                params: params.clone(),
                witness,
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

    fn build_header(&self, ctx: &impl OracleCertifyContext, target: OracleTarget) -> LyquidResult<OracleHeader> {
        let proposer = ctx.get_node_id();
        let config_hash = match target {
            OracleTarget::EVM(_) => self.config_hash_evm,
            OracleTarget::LVM(_) => self.config_hash_lvm,
        };

        // Populate epoch from instance state and derive a nonce per call.
        let nonce = Hash::from_slice(&lyquor_api::random_bytes(32)?)
            .map_err(|_| LyquidError::LyquidRuntime("OracleSrc: failed to obtain random nonce.".into()))?
            .into();
        let epoch: u32 = 0; // TODO: use the cached epoch from instance state.

        Ok(OracleHeader {
            proposer,
            target,
            config_hash: config_hash.into(),
            epoch,
            nonce,
        })
    }

    /// Two-phase oracle flow:
    /// 1) Collect signed inputs from committee via UPC `propose`.
    /// 2) Aggregate them, then run normal `validate` voting with witness.
    ///
    /// `args` is forwarded to committee `propose(...)` (encoded by fields by the caller).
    /// `aggregate` is executed on proposer to build the final call input bytes.
    pub fn propose_and_certify<F, T>(
        &self, ctx: &impl OracleCertifyContext, origin: Address, method: String, target: OracleTarget, args: Bytes,
        aggregate: F,
    ) -> LyquidResult<Option<CallParams>>
    where
        T: Serialize + serde::de::DeserializeOwned,
        F: FnOnce(&[ProposeAttestation<T>]) -> LyquidResult<Bytes>,
    {
        if self.threshold == 0 ||
            self.committee.len() > u16::MAX as usize ||
            self.committee.len() < self.threshold as usize
        {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "Invalid OracleConfig(committee.len()={}, threshold={}).",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }

        let lyquid = ctx.get_lyquid_id();
        let header = self.build_header(ctx, target)?;
        let args_for_witness = args.clone();

        // Collect signed values.
        let attestations: Option<Vec<ProposeAttestation>> = lyquor_api::universal_procedural_call(
            lyquid,
            Some(format!("oracle::committee::{}", self.id)),
            "propose".into(),
            lyquor_primitives::encode_by_fields!(msg: ProposeRequest = ProposeRequest {
                header,
                args: args.clone(),
            }),
            Some(
                lyquor_primitives::encode_by_fields!(
                    callee: Vec<NodeID> = self.committee.keys().cloned().collect(),
                    header: OracleHeader = header,
                    args: Bytes = args
                )
                .into(),
            ),
        )
        .and_then(|r| lyquor_primitives::decode_object(&r).ok_or(LyquidError::LyquorOutput))?;

        let Some(attestations) = attestations else {
            return Ok(None);
        };

        // Convert to typed attestations for the user-provided aggregate function.
        let typed_atts = attestations
            .iter()
            .map(|a| {
                Ok(ProposeAttestation {
                    from: a.from,
                    value: lyquor_primitives::decode_object(&a.value).ok_or(LyquidError::LyquorInput)?,
                    sig: a.sig.clone(),
                })
            })
            .collect::<LyquidResult<Vec<ProposeAttestation<T>>>>()?;

        // Build final call input and forward witness.
        let input = aggregate(&typed_atts)?;
        let witness = Bytes::from(lyquor_primitives::encode_object(&ProposeWitness {
            header,
            args: args_for_witness,
            attestations: typed_atts,
        }));
        self.certify_with_header_and_witness(ctx, origin, method, input, header, witness)
    }

    pub fn __pre_validation(&self, header: &OracleHeader) -> bool {
        let hash = match header.target {
            OracleTarget::LVM(_) => self.config_hash_lvm,
            OracleTarget::EVM(_) => self.config_hash_evm,
        };
        hash == *header.config_hash
    }

    pub fn __post_validation(
        &self, header: OracleHeader, params: CallParams, approval: bool,
    ) -> LyquidResult<ValidateResponse> {
        let preimage = OraclePreimage {
            header,
            params,
            approval,
        };

        let cipher = OracleSrc::cipher_for_target(&header.target);
        let m = match header.target {
            OracleTarget::EVM(_) => eth::OraclePreimage::try_from(preimage).unwrap().to_preimage(),
            OracleTarget::LVM(_) => preimage.to_preimage(),
        };

        let sig = lyquor_api::sign(m.into(), cipher)?;
        Ok(ValidateResponse { approval, sig })
    }

    pub fn __post_propose(&self, header: OracleHeader, args: Bytes, value: Bytes) -> LyquidResult<ProposeResponse> {
        let preimage = ProposePreimage {
            header,
            args,
            value: value.clone(),
        };

        let cipher = OracleSrc::cipher_for_target(&header.target);
        let m = match header.target {
            OracleTarget::EVM(_) => eth::ProposePreimage::try_from(preimage).unwrap().to_preimage(),
            OracleTarget::LVM(_) => preimage.to_preimage(),
        };

        let sig = lyquor_api::sign(m.into(), cipher)?;
        Ok(ProposeResponse { value, sig })
    }
}

/// UPC cache state for aggregation.
pub struct Aggregation {
    header: OracleHeader,
    yea_msg: Bytes,
    nay_msg: Bytes,

    // Voting state
    voted: super::volatile::HashSet<NodeID>,
    yea_sigs: Vec<(OracleSigner, Bytes)>,
    yea: u16,
    nay: u16,
    result: Option<Option<OracleCert>>,
}

/// UPC cache state for propose phrase aggregation.
pub struct ProposeAggregation {
    header: OracleHeader,
    args: Bytes,
    // Collected unique responders (regardless of validity) to detect early failure.
    attempted: super::volatile::HashSet<NodeID>,
    attestations: Vec<ProposeAttestation>,
    result: Option<Option<Vec<ProposeAttestation>>>,
}

impl ProposeAggregation {
    pub fn new(header: OracleHeader, args: Bytes) -> Self {
        Self {
            header,
            args,
            attempted: super::volatile::new_hashset(),
            attestations: Vec::new(),
            result: None,
        }
    }

    pub fn add_response(
        &mut self, node: NodeID, resp: ProposeResponse, oracle: &OracleSrc,
    ) -> Option<Option<Vec<ProposeAttestation>>> {
        if self.result.is_some() || self.attempted.contains(&node) {
            return self.result.clone();
        }

        let cipher = OracleSrc::cipher_for_target(&self.header.target);
        let ok = oracle
            .pubkey_for_cipher(&node, cipher)
            .and_then(|pk| {
                let preimage = ProposePreimage {
                    header: self.header,
                    args: self.args.clone(),
                    value: resp.value.clone(),
                };
                let m = match self.header.target {
                    OracleTarget::EVM(_) => eth::ProposePreimage::try_from(preimage).unwrap().to_preimage(),
                    OracleTarget::LVM(_) => preimage.to_preimage(),
                };
                super::lyquor_api::verify(m.into(), cipher, resp.sig.clone(), pk).ok()
            })
            .unwrap_or(false);

        if self.attempted.insert(node) {
            if ok {
                self.attestations.push(ProposeAttestation {
                    from: node,
                    value: resp.value,
                    sig: resp.sig,
                });
            }
        }

        if self.attestations.len() >= oracle.threshold as usize {
            self.result = Some(Some(self.attestations.clone()));
        } else if oracle.committee.len() - (self.attempted.len() - self.attestations.len()) < oracle.threshold as usize
        {
            // Early failure: impossible to reach threshold with remaining nodes.
            self.result = Some(None);
        }

        self.result.clone()
    }
}

fn verify_oracle_cert(oc: &OracleCert, msg: Bytes, config: &OracleConfigDest, config_hash: &Hash) -> bool {
    let mut config = config;
    let _new_config;
    match &oc.new_config {
        Some(new_config) => {
            let hash: HashBytes = new_config.to_hash().into();
            if hash != oc.header.config_hash {
                // Config mismatch.
                return false;
            }
            _new_config = (&*new_config).into();
            config = &_new_config;
        }
        None => {
            if &*oc.header.config_hash != config_hash {
                // Config mismatch.
                return false;
            }
        }
    }

    if oc.signers.len() != oc.signatures.len() {
        // Malformed certificate.
        return false;
    }

    if oc.signers.len() < config.threshold as usize {
        // Threshold not met.
        return false
    }

    for (idx, sig) in oc
        .signers
        .iter()
        .zip(oc.signatures.iter().take(config.threshold as usize))
    {
        let idx = (*idx) as usize;
        let signer = if idx < config.committee.len() {
            &config.committee[idx]
        } else {
            // Invalid signer index.
            return false
        };
        if !super::lyquor_api::verify(
            msg.clone(),
            Cipher::Ed25519,
            sig.clone(),
            Bytes::copy_from_slice(&signer.1),
        )
        .unwrap_or(false)
        {
            return false;
        }
    }
    true
}

impl Aggregation {
    pub fn new(header: OracleHeader, yea_msg: Bytes, nay_msg: Bytes) -> Self {
        Self {
            header,
            yea_msg,
            nay_msg,
            voted: super::volatile::new_hashset(),
            yea_sigs: Vec::new(),
            yea: 0,
            nay: 0,
            result: None,
        }
    }

    pub fn add_response(
        &mut self, node: NodeID, resp: ValidateResponse, oracle: &OracleSrc,
    ) -> Option<Option<OracleCert>> {
        if self.result.is_some() || self.voted.contains(&node) {
            return self.result.clone();
        }

        // Delegate signature verification to the host-side API. If verification fails or the
        // host API errors, treat this as a failed vote.
        let cipher = OracleSrc::cipher_for_target(&self.header.target);
        let ok = oracle
            .pubkey_for_cipher(&node, cipher)
            .and_then(|pk| {
                super::lyquor_api::verify(
                    if resp.approval { &self.yea_msg } else { &self.nay_msg }.clone(),
                    cipher,
                    resp.sig.clone(),
                    pk,
                )
                .ok()
            })
            .unwrap_or(false);

        if self.voted.insert(node) {
            if ok {
                // A node can only vote once.
                match resp.approval {
                    true => {
                        self.yea_sigs.push((
                            OracleSigner {
                                id: node,
                                key: oracle.pubkey_for_cipher(&node, cipher).unwrap(),
                            },
                            resp.sig.clone(),
                        ));
                        self.yea += 1
                    }
                    false => self.nay += 1,
                }
            }
        }

        crate::println!("yea = {}, thres = {}", self.yea, oracle.threshold);
        if self.yea >= oracle.threshold {
            let consolidated = &oracle.config;
            // Build a look up table to find the signer's index.
            let mut index_of = std::collections::HashMap::new();
            for (i, s) in consolidated.committee.iter().enumerate() {
                index_of.insert(s.id, i);
            }
            let mut signers: Vec<u16> = Vec::new();
            let mut signatures = Vec::new();
            for (signer, sig) in self.yea_sigs.clone().into_iter() {
                if let Some(i) = index_of.get(&signer.id).copied() {
                    signers.push(i as u16);
                    signatures.push(sig);
                }
            }

            self.result = Some(Some(OracleCert {
                header: self.header,
                new_config: Some(consolidated.to_wire(cipher)), // TODO
                signers,
                signatures,
            }))
        } else if oracle.committee.len() - (self.voted.len() - self.yea as usize) < oracle.threshold as usize {
            self.result = Some(None)
        }
        self.result.clone()
    }
}

struct OracleConfigDest {
    committee: network::Vec<(NodeID, network::Vec<u8>)>,
    threshold: u16,
}

impl Default for OracleConfigDest {
    fn default() -> Self {
        Self {
            committee: network::new_vec(),
            threshold: 0,
        }
    }
}

impl From<&OracleConfig> for OracleConfigDest {
    fn from(oc: &OracleConfig) -> Self {
        let mut committee = Vec::with_capacity_in(oc.committee.len(), network::Alloc);
        for signer in oc.committee.iter() {
            committee.push((signer.id, signer.key.to_vec_in(network::Alloc)));
        }
        Self {
            committee,
            threshold: oc.threshold,
        }
    }
}

/// Per-topic destination-chain oracle state.
pub struct OracleDest {
    // The following states are used for certificate verification.
    // Active oracle config for the topic.
    config: OracleConfigDest,
    // Hash of _config for the topic.
    config_hash: HashBytes,
    // The following variables are used to ensure a certified call is at most invoked once.
    // Epoch number.
    epoch: u32,
    used_nonce: network::HashSet<Hash>,
}

impl Default for OracleDest {
    fn default() -> Self {
        Self {
            config: OracleConfigDest::default(),
            config_hash: [0; 32].into(),
            epoch: 0,
            used_nonce: network::new_hashset(),
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

    fn update_config(&mut self, config: OracleConfig, config_hash: HashBytes) -> bool {
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
        self.config = (&config).into();
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
        let msg = OraclePreimage {
            header: oc.header,
            params,
            approval: true,
        }
        .to_preimage()
        .into();

        // Verify the validity of the OracleCert.
        if !verify_oracle_cert(&oc, msg, &self.config, &self.config_hash) {
            // Invalid call certificate.
            return false;
        }

        if let Some(config) = oc.new_config {
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
