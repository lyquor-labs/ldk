//! Destination-side oracle verification and replay protection.
//!
//! Destination state is authoritative for oracle settlement: config, epoch, and nonce set are
//! enforced here to gate certified calls.

use super::*;
use lyquor_primitives::oracle::{
    OracleConfig as OracleConfigWire, OracleConfigDelta as OracleConfigDeltaWire, OracleSigner, ValidatePreimage,
};
use lyquor_primitives::{Address, Bytes, CallParams, Hash, HashBytes, InputABI};

// Mirrors `eth/src/lib/oracle.sol::_verifyOracleCert` for the LVM destination path.
fn verify_oracle_cert(oc: &OracleCert, params: &CallParams, config: &OracleConfig) -> Result<(), ()> {
    if oc.signers.len() != oc.signatures.len() {
        // Malformed certificate.
        return Err(());
    }
    let threshold = config.threshold as usize;
    if oc.signers.len() < config.threshold as usize {
        // Threshold not met.
        return Err(());
    }

    let msg: Bytes = ValidatePreimage {
        header: oc.header.clone(),
        params: params.clone(),
        approval: true,
    }
    .to_preimage()
    .into();

    let cipher = oc.header.target.cipher();
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
    Ok(())
}

fn is_delta_canonical(delta: &OracleConfigDeltaWire) -> bool {
    // Canonical delta form requires strictly increasing IDs in each list.
    if !delta.upsert.windows(2).all(|w| w[0].id < w[1].id) || !delta.remove.windows(2).all(|w| w[0] < w[1]) {
        return false;
    }

    // Upsert/remove sets must be disjoint.
    let mut i = 0usize;
    let mut j = 0usize;
    while i < delta.remove.len() && j < delta.upsert.len() {
        let rid = delta.remove[i];
        let uid = delta.upsert[j].id;
        if rid == uid {
            return false;
        }
        if rid < uid {
            i += 1;
        } else {
            j += 1;
        }
    }
    true
}

/// Oracle configuration used by the destination.
#[derive(Clone)]
struct OracleConfig {
    committee: HashMap<SignerID, Vec<u8>>,
    threshold: u16,
}

impl OracleConfig {
    fn new() -> Self {
        Self {
            committee: new_hashmap(),
            threshold: 0,
        }
    }

    #[inline]
    fn is_valid(&self) -> bool {
        self.threshold != 0 &&
            self.committee.len() <= u16::MAX as usize &&
            self.committee.len() >= self.threshold as usize
    }

    fn to_wire(&self) -> OracleConfigWire {
        let mut committee: Vec<_> = self
            .committee
            .iter()
            .map(|(id, key)| OracleSigner {
                id: *id,
                key: key.clone().into(),
            })
            .collect();
        committee.sort_by_key(|s| s.id);
        OracleConfigWire {
            committee,
            threshold: self.threshold,
        }
    }

    fn config_after_delta(&self, delta: &OracleConfigDeltaWire) -> Option<Self> {
        if !is_delta_canonical(delta) {
            return None;
        }
        let mut next = self.clone();
        for id in delta.remove.iter() {
            next.committee.remove(id);
        }
        for s in delta.upsert.iter() {
            next.committee.insert(s.id, s.key.to_vec());
        }
        if let Some(threshold) = delta.threshold {
            next.threshold = threshold;
        }
        if !next.is_valid() {
            return None;
        }
        Some(next)
    }
}

/// Per-topic network state for the destination (certified call execution) chain.
pub struct OracleDest {
    // Active oracle config for the topic.
    config: OracleConfig,
    // Hash of _config for the topic.
    config_hash: HashBytes,
    // Nonce of settled calls in the current epoch, used to ensure a certified call is at most
    // invoked once.
    used_nonce: HashSet<Hash>,
    // Epoch number.
    epoch: u32,
}

impl Default for OracleDest {
    fn default() -> Self {
        Self {
            config: OracleConfig::new(),
            config_hash: [0; 32].into(),
            used_nonce: new_hashset(),
            epoch: 0,
        }
    }
}

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

    pub fn get_config(&self) -> lyquor_primitives::oracle::OracleConfig {
        self.config.to_wire()
    }

    pub fn signer_node_id(&self, id: SignerID) -> Option<NodeID> {
        let key = self.config.committee.get(&id)?;
        let key: [u8; 32] = key.as_slice().try_into().ok()?;
        Some(NodeID::from(key))
    }

    fn verify_lvm_binding(me: LyquidID, params: &CallParams, oc: &OracleCert) -> bool {
        // Ensure this certificate belongs to the active sequence backend.
        let backend = match lyquor_api::sequence_backend_id() {
            Ok(id) => id,
            Err(_) => return false,
        };
        if oc.header.target.seq_id != backend {
            return false;
        }
        if params.abi != InputABI::Lyquor {
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
        true
    }

    fn update(&mut self, header: &OracleHeader, next_config: Option<OracleConfig>) -> bool {
        let update_config = next_config.is_some();
        let nonce: Hash = header.nonce.clone().into();
        let epoch_delta = match header.epoch.checked_sub(self.epoch) {
            Some(delta) => delta,
            None => return false,
        };
        match epoch_delta {
            0 => {
                if update_config ||
                    self.used_nonce.contains(&nonce) ||
                    self.used_nonce.len() >= Self::MAX_NONCE_PER_EPOCH
                {
                    return false;
                }
            }
            1 => {
                if !update_config && self.used_nonce.len() < Self::MIN_NONCE_NEXT_EPOCH {
                    return false;
                }
                self.epoch = header.epoch;
                self.used_nonce.clear();
                if let Some(config) = next_config {
                    self.config = config;
                    self.config_hash = header.config_hash.clone();
                }
            }
            _ => return false,
        }

        // Mark the certified call's nonce as used.
        self.used_nonce.insert(nonce)
    }

    pub fn verify(&mut self, me: LyquidID, params: lyquor_primitives::CallParams, oc: &OracleCert) -> bool {
        // Mirrors eth/src/lib/oracle.sol::verify for the LVM destination path.
        if !Self::verify_lvm_binding(me, &params, oc) {
            return false;
        }
        if oc.header.epoch != self.epoch {
            return false;
        }
        // Verify certificate signatures/config hash against the signed preimage.
        if oc.header.config_hash != self.config_hash {
            return false;
        }
        if verify_oracle_cert(oc, &params, &self.config).is_err() {
            // Invalid call certificate.
            return false;
        }
        self.update(&oc.header, None)
    }

    pub fn verify_epoch_advance(
        &mut self, me: LyquidID, caller: Address, topic: &str, config_delta: &OracleConfigDeltaWire, oc: &OracleCert,
    ) -> bool {
        let params = CallParams {
            origin: Address::ZERO,
            caller,
            group: "oracle::internal".to_string(),
            method: ADVANCE_EPOCH_METHOD.into(),
            input: encode_by_fields!(
                topic: String = topic.to_string(),
                config_delta: OracleConfigDeltaWire = config_delta.clone()
            )
            .into(),
            abi: InputABI::Lyquor,
        };
        if !Self::verify_lvm_binding(me, &params, oc) {
            return false;
        }
        if oc.header.epoch != self.epoch.wrapping_add(1) {
            return false;
        }
        let next_config =
            if config_delta.upsert.is_empty() && config_delta.remove.is_empty() && config_delta.threshold.is_none() {
                None
            } else {
                match self.config.config_after_delta(config_delta) {
                    Some(config) => Some(config),
                    None => return false,
                }
            };
        let config_hash = match &next_config {
            Some(config) => config.to_wire().to_hash().into(),
            None => self.config_hash.clone(),
        };
        if oc.header.config_hash != config_hash {
            return false;
        }
        if verify_oracle_cert(oc, &params, &self.config).is_err() {
            return false;
        }
        self.update(&oc.header, next_config)
    }
}
