//! Destination-side oracle verification and replay protection.
//!
//! Destination state is authoritative for oracle settlement: config, epoch, and nonce set are
//! enforced here to gate certified calls.

use super::protocol::is_epoch_advance_params;
use super::*;
use lyquor_primitives::oracle::{
    OracleConfig as OracleConfigWire, OracleConfigDelta as OracleConfigDeltaWire, OracleSigner, ValidatePreimage,
};
use lyquor_primitives::{Bytes, CallParams, Hash, HashBytes, InputABI};

// Mirrors `eth/src/lib/oracle.sol::_verifyOracleCert` for the LVM destination path.
fn verify_oracle_cert(
    oc: &OracleCert, params: &CallParams, config: &OracleConfigDest, config_hash: &Hash,
) -> Result<Option<OracleConfigDeltaWire>, ()> {
    let mut config_delta = None;
    let topic = lyquor_primitives::oracle::topic_from_group(params.group.as_str());
    if is_epoch_advance_params(topic, &params) {
        let payload = lyquor_primitives::decode_by_fields!(params.input.as_ref(), config_delta: OracleConfigDeltaWire)
            .ok_or(())?;
        let delta = payload.config_delta;
        let hash = config.hash_after_delta(&delta).ok_or(())?;
        if hash != oc.header.config_hash {
            return Err(());
        }
        config_delta = Some(delta);
    } else if &*oc.header.config_hash != config_hash {
        // Config mismatch.
        return Err(());
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
        params: params.clone(),
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
    Ok(config_delta)
}

/// Oracle configuration used by the destination.
#[derive(Clone)]
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

    fn hash_after_delta(&self, delta: &OracleConfigDeltaWire) -> Option<HashBytes> {
        if !Self::is_delta_canonical(delta) {
            return None;
        }
        let mut next = self.clone();
        next.apply_delta_in_place(delta);
        if !next.is_valid() {
            return None;
        }
        Some(next.to_wire().to_hash().into())
    }

    fn apply_delta_in_place(&mut self, delta: &OracleConfigDeltaWire) {
        for id in delta.remove.iter() {
            self.committee.remove(id);
        }
        for s in delta.upsert.iter() {
            self.committee.insert(s.id, s.key.to_vec());
        }
        if let Some(threshold) = delta.threshold {
            self.threshold = threshold;
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

    pub(crate) fn get_epoch(&self) -> u32 {
        self.epoch
    }

    pub(crate) fn get_config_hash(&self) -> &HashBytes {
        &self.config_hash
    }

    pub(crate) fn signer_node_id(&self, id: SignerID) -> Option<NodeID> {
        let key = self.config.committee.get(&id)?;
        let key: [u8; 32] = key.as_slice().try_into().ok()?;
        Some(NodeID::from(key))
    }

    /// Check whether `(epoch, nonce)` would be accepted, without mutating state.
    fn can_record_nonce(&self, epoch: u32, nonce: Hash, has_config_update: bool) -> bool {
        if epoch < self.epoch {
            return false;
        }
        if epoch > self.epoch {
            return has_config_update || self.used_nonce.len() >= Self::MIN_NONCE_NEXT_EPOCH;
        }
        self.used_nonce.len() < Self::MAX_NONCE_PER_EPOCH && !self.used_nonce.contains(&nonce)
    }

    /// Record a nonce in the given epoch. Returns false if invalid.
    fn record_nonce(&mut self, epoch: u32, nonce: Hash, has_config_update: bool) -> bool {
        if epoch < self.epoch {
            // Stale epoch.
            return false;
        }

        // Enter a new epoch if higher.
        if epoch > self.epoch {
            if !has_config_update && self.used_nonce.len() < Self::MIN_NONCE_NEXT_EPOCH {
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
        // Mirrors eth/src/lib/oracle.sol::verify for the LVM destination path.

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

        // Verify certificate signatures/config hash against the signed preimage.
        let config_delta = match verify_oracle_cert(oc, &params, &self.config, &self.config_hash) {
            Ok(cfg) => cfg,
            Err(_) => {
                // Invalid call certificate.
                return false;
            }
        };

        let has_config_update = config_delta
            .as_ref()
            .is_some_and(|_| oc.header.config_hash != self.config_hash);
        let nonce: Hash = oc.header.nonce.clone().into();
        if !self.can_record_nonce(oc.header.epoch, nonce.clone(), has_config_update) {
            return false;
        }
        if let Some(delta) = config_delta.as_ref() {
            self.config.apply_delta_in_place(delta);
            self.config_hash = oc.header.config_hash.clone();
        }
        // Record nonce to prevent replay.
        if !self.record_nonce(oc.header.epoch, nonce, has_config_update) {
            return false;
        }
        true
    }
}
