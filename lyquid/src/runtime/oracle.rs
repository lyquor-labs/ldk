use super::{Deserialize, LyquidError, LyquidID, LyquidResult, NodeID, Serialize, StateAccessor, lyquor_api};
pub use lyquor_primitives::oracle::{
    OracleCert, OracleConfig, OracleHeader, OraclePreimage, OracleSigner, OracleTarget, eth,
};
use lyquor_primitives::{Address, Bytes, CallParams, Hash, HashBytes, InputABI, Signature};

pub struct Digest {
    pub lvm: Hash,
    pub evm: Hash,
}

impl Digest {
    const ZERO: Digest = Digest {
        lvm: Hash::from_bytes([0; 32]),
        evm: Hash::from_bytes([0; 32]),
    };
}

/// UPC message sent to each validator.
///
/// The validator (signer) will check config hash to see if it's consistent with its oracle state
/// as of the given network state version, and then run `validate`, a signature will be
/// automatically signed, and respond to the caller with `validate()`'s result (true/false).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Request {
    pub header: OracleHeader,
    pub params: CallParams,
}

/// UPC message responded from each validator.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Response {
    pub approval: bool,
    pub sig: Signature,
}

/// Network state for the source (call generation) chain.
pub struct OracleSrc {
    id: &'static str,
    threshold: usize,
    committee: super::network::HashMap<NodeID, OracleSigner>,
    config_hash: Digest,
    config_update: bool,
}

impl OracleSrc {
    fn updated_config(&mut self) {
        let config = self.consolidate_config();
        self.config_hash = Digest {
            lvm: config.to_hash(),
            evm: eth::OracleConfig {
                committee: config
                    .committee
                    .into_iter()
                    .map(|s| lyquor_api::get_ed25519_address(s.key).unwrap().unwrap())
                    .collect(), // FIMXE
                threshold: config.threshold as u16,
            }
            .to_hash(),
        };
        self.config_update = true;
    }

    fn consolidate_config(&self) -> OracleConfig {
        let committee: Vec<OracleSigner> = self.committee.values().cloned().collect();
        OracleConfig {
            committee,
            threshold: self.threshold,
        }
    }

    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            threshold: 0,
            committee: super::network::new_hashmap(),
            config_hash: Digest::ZERO,
            config_update: false,
        }
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&mut self, id: NodeID) -> bool {
        let key = lyquor_primitives::PublicKey(id.0);
        let signer = OracleSigner { id, key };
        if self.committee.insert(id, signer).is_some() {
            return false;
        }
        self.updated_config();
        true
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node(&mut self, id: &NodeID) -> bool {
        if self.committee.remove(id).is_none() {
            return false;
        }
        self.updated_config();
        true
    }

    /// Get the committee size.
    pub fn len(&self) -> usize {
        self.committee.len()
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold(&mut self, new_thres: usize) {
        if new_thres == self.threshold {
            return;
        }
        self.threshold = new_thres;
        self.updated_config();
    }

    /// Generate a certificate that testifies the validity of an oracle call to a target network
    /// (sequence backend).
    pub fn certify(
        &self, ctx: &impl OracleCertifyContext, origin: Address, method: String, input: Bytes, target: OracleTarget,
    ) -> LyquidResult<Option<CallParams>> {
        if self.threshold == 0 || self.committee.len() < self.threshold || self.committee.len() > u16::MAX as usize {
            return Err(crate::LyquidError::LyquidRuntime(format!(
                "Invalid OracleConfig(committee.len()={}, threshold={}).",
                self.threshold,
                self.committee.len()
            ))
            .into());
        }

        let proposer = ctx.get_node_id();
        let lyquid = ctx.get_lyquid_id();

        let (abi, config_hash) = match target {
            OracleTarget::EVM(_) => (InputABI::Eth, self.config_hash.evm),
            OracleTarget::LVM(_) => (InputABI::Lyquor, self.config_hash.lvm),
        };

        // The network fn call to be certified.
        let mut params = CallParams {
            origin,
            caller: origin, //lyquid.into(),
            group: self.id.into(),
            method,
            input,
            abi,
        };

        // Populate epoch from instance state and derive a nonce per call.
        let nonce = Hash::from_slice(&lyquor_api::random_bytes(32)?)
            .map_err(|_| LyquidError::LyquidRuntime("OracleSrc: failed to obtain random nonce.".into()))?
            .into();
        let epoch: u32 = 0; // TODO: use the cached epoch from instance state.
        let header = OracleHeader {
            proposer,
            target,
            config_hash: config_hash.into(),
            epoch,
            nonce,
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

        let (yay_msg, nay_msg) = match target {
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
            lyquor_primitives::encode_by_fields!(msg: Request = Request {
                header,
                params: params.clone(),
            }),
            Some(
                lyquor_primitives::encode_by_fields!(
                    // Use oracle macro expected field "callee" for callee list and pass verification context.
                    callee: Vec<NodeID> = self.committee(),
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

    pub fn committee(&self) -> Vec<NodeID> {
        self.committee.keys().cloned().collect()
    }

    pub fn config_hash(&self) -> &Digest {
        &self.config_hash
    }
}

/// UPC cache state for aggregation.
pub struct Aggregation {
    header: OracleHeader,
    yea_msg: Bytes,
    nay_msg: Bytes,

    // Voting state
    voted: super::volatile::HashSet<NodeID>,
    yea_sigs: Vec<(OracleSigner, Signature)>,
    yea: usize,
    nay: usize,
    result: Option<Option<OracleCert>>,
}

fn verify_oracle_cert<'a>(oc: &'a OracleCert, msg: Bytes, mut config: &'a OracleConfig, config_hash: &Hash) -> bool {
    match &oc.new_config {
        Some(new_config) => {
            let hash: HashBytes = new_config.to_hash().into();
            if hash != oc.header.config_hash {
                // Config mismatch.
                return false;
            }
            config = new_config
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

    if oc.signers.len() < config.threshold {
        // Threshold not met.
        return false
    }

    for (idx, sig) in oc.signers.iter().zip(oc.signatures.iter().take(config.threshold)) {
        let idx = (*idx) as usize;
        let signer = if idx < config.committee.len() {
            &config.committee[idx]
        } else {
            // Invalid signer index.
            return false
        };
        if !super::lyquor_api::verify(msg.clone(), lyquor_primitives::Cipher::Ed25519, sig.clone(), signer.key)
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

    pub fn add_response(&mut self, node: NodeID, resp: Response, oracle: &OracleSrc) -> Option<Option<OracleCert>> {
        // Delegate signature verification to the host-side API. If verification fails or the
        // host API errors, treat this as a failed vote.
        let ok = oracle
            .committee
            .get(&node)
            .and_then(|s| {
                super::lyquor_api::verify(
                    match resp.approval {
                        true => &self.yea_msg,
                        false => &self.nay_msg,
                    }
                    .clone(),
                    match self.header.target {
                        OracleTarget::EVM(_) => lyquor_primitives::Cipher::Secp256k1,
                        OracleTarget::LVM(_) => lyquor_primitives::Cipher::Ed25519,
                    },
                    resp.sig.clone(),
                    s.key,
                )
                .ok()
            })
            .unwrap_or(false);
        if ok && self.voted.insert(node) {
            match resp.approval {
                true => {
                    self.yea_sigs
                        .push((*oracle.committee.get(&node).unwrap(), resp.sig.clone()));
                    self.yea += 1
                }
                false => self.nay += 1,
            }
        }

        if self.result.is_none() {
            crate::println!("yea = {}, thres = {}", self.yea, oracle.threshold);
            if self.yea >= oracle.threshold {
                let config = oracle.consolidate_config();

                // Build a look up table to find the signer's index.
                let mut index_of = std::collections::HashMap::new();
                for (i, s) in config.committee.iter().enumerate() {
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
                    new_config: if oracle.config_update {
                        Some(config.clone())
                    } else {
                        None
                    },
                    signers,
                    signatures,
                }))
            } else if oracle.committee.len() - self.nay < oracle.threshold {
                self.result = Some(None)
            }
        }
        self.result.clone()
    }
}

/// Per-topic destination-chain oracle state.
pub struct OracleDest {
    // The following states are used for certificate verification.
    // Active oracle config for the topic.
    config: OracleConfig,
    // Hash of _config for the topic.
    config_hash: HashBytes,
    // The following variables are used to ensure a certified call is at most invoked once.
    // Epoch number.
    epoch: u32,
    used_nonce: super::network::HashSet<Hash>,
}

impl Default for OracleDest {
    fn default() -> Self {
        Self {
            config: OracleConfig {
                threshold: 0,
                committee: Vec::new(),
            },
            config_hash: [0; 32].into(),
            epoch: 0,
            used_nonce: super::network::new_hashset(),
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
        if config.committee.len() > u16::MAX as usize {
            // Too many signers.
            return false;
        }
        if config.threshold == 0 || config.threshold > config.committee.len() {
            // Invalid threshold.
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
