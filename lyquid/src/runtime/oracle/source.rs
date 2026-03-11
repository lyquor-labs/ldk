//! Source-side local oracle cache and source wrapper APIs.
//!
//! This cache is not authoritative consensus state. It is a local view used to drive source
//! voting/certification liveness before target-side verification.

use super::*;
use hashbrown::hash_map::Entry;
use lyquor_primitives::oracle::{
    OracleConfig as OracleConfigWire, OracleConfigDelta as OracleConfigDeltaWire, OracleSigner, eth,
};
use lyquor_primitives::{Address, Bytes, Cipher, Hash};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signer {
    pub id: SignerID,
    key_lvm: [u8; 32], // ed25519 native key
    key_evm: Address,  // Secp256k1 signer's address
}

impl Signer {
    /// Return the key/address that is used for verification.
    pub fn get_verifying_key(&self, cipher: Cipher) -> Bytes {
        match cipher {
            Cipher::Ed25519 => Bytes::copy_from_slice(&self.key_lvm),
            Cipher::Secp256k1 => Bytes::copy_from_slice(self.key_evm.as_ref()),
        }
    }

    /// Get the wire format for a platform, determined by `cipher`.
    pub fn to_wire(&self, cipher: Cipher) -> OracleSigner {
        OracleSigner {
            id: self.id,
            key: self.get_verifying_key(cipher),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OracleConfig {
    pub committee: HashMap<NodeID, Signer>,
    pub threshold: u16,
    pub epoch: u32,
}

impl OracleConfig {
    fn new() -> Self {
        Self {
            committee: new_hashmap(),
            threshold: 0,
            epoch: 0,
        }
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.threshold != 0 &&
            self.committee.len() <= u16::MAX as usize &&
            self.committee.len() >= self.threshold as usize
    }

    fn to_wire(&self, cipher: Cipher) -> OracleConfigWire {
        let mut committee: Vec<_> = self.committee.iter().map(|(_, s)| s.to_wire(cipher)).collect();
        // The canonical representation of a committee set is sorted by signer IDs.
        committee.sort_by_key(|s| s.id);
        OracleConfigWire {
            committee,
            threshold: self.threshold,
        }
    }

    #[inline]
    fn empty() -> &'static Self {
        static EMPTY: std::sync::OnceLock<OracleConfig> = std::sync::OnceLock::new();
        EMPTY.get_or_init(Self::new)
    }
}

#[derive(Clone, PartialEq, Eq)]
enum CommitteeChange {
    Upsert(Signer),
    Remove(SignerID),
}

#[derive(Clone, PartialEq, Eq, Default)]
struct OracleConfigDelta {
    committee: HashMap<NodeID, CommitteeChange>,
    threshold: Option<u16>,
}

impl OracleConfigDelta {
    pub fn is_empty(&self) -> bool {
        self.committee.is_empty() && self.threshold.is_none()
    }

    pub fn to_wire(&self, cipher: Cipher) -> OracleConfigDeltaWire {
        let mut upsert = Vec::new();
        let mut remove = Vec::new();
        for (_node, op) in self.committee.iter() {
            match op {
                CommitteeChange::Upsert(signer) => {
                    upsert.push(signer.to_wire(cipher));
                }
                CommitteeChange::Remove(id) => remove.push(*id),
            }
        }
        upsert.sort_by_key(|s| s.id);
        remove.sort();
        OracleConfigDeltaWire {
            upsert,
            remove,
            threshold: self.threshold,
        }
    }
}

#[derive(Clone)]
pub struct TargetState {
    cipher: Cipher,
    current: OracleConfig,
    staging: OracleConfig,
    staging_delta: OracleConfigDelta,

    // Cached data for fast voting/checking.
    current_hash: Hash,
    staging_hash: Hash,
    staging_delta_wire: OracleConfigDeltaWire,
    staging_cache_dirty: bool,
}

#[doc(hidden)]
pub struct OracleSrc {
    topic: String,
    targets: HashMap<OracleTarget, TargetState>,
    next_signer_id: SignerID,
}

fn config_hash(config: &OracleConfig, cipher: Cipher) -> Hash {
    match cipher {
        Cipher::Ed25519 => config.to_wire(Cipher::Ed25519).to_hash(),
        Cipher::Secp256k1 => eth::OracleConfig::from(config.to_wire(Cipher::Secp256k1)).to_hash(),
    }
}

impl TargetState {
    fn new(target: &OracleTarget) -> Self {
        let cipher = match target.target {
            OracleServiceTarget::LVM(_) => Cipher::Ed25519,
            OracleServiceTarget::EVM { .. } => Cipher::Secp256k1,
        };
        let current = OracleConfig::new();
        let mut staging = current.clone();
        staging.epoch += 1;
        let staging_delta = OracleConfigDelta::default();
        Self {
            cipher,
            current,
            staging_delta,
            staging,
            current_hash: Hash::from_bytes([0; 32]),
            staging_hash: Hash::from_bytes([0; 32]),
            staging_delta_wire: OracleConfigDeltaWire {
                upsert: Vec::new(),
                remove: Vec::new(),
                threshold: None,
            },
            staging_cache_dirty: true,
        }
    }

    #[inline]
    fn invalidate_staging_cache(&mut self) {
        self.staging_cache_dirty = true;
    }

    #[inline]
    fn ensure_staging_cache(&mut self) {
        if self.staging_cache_dirty {
            self.staging_hash = config_hash(&self.staging, self.cipher);
            self.staging_delta_wire = self.staging_delta.to_wire(self.cipher);
            self.staging_cache_dirty = false;
        }
    }

    fn on_epoch_update(&mut self, target_state: OracleEpochInfo) -> bool {
        let target_epoch = target_state.epoch;
        let target_hash: Hash = <[u8; 32]>::from(target_state.config_hash).into();
        // Ignore stale epoch.
        if target_epoch < self.current.epoch {
            return false;
        }
        // Same epoch: only hash-consistency check.
        if target_epoch == self.current.epoch {
            return self.current_hash == target_hash;
        }

        self.ensure_staging_cache();
        if target_epoch != self.staging.epoch || target_hash != self.staging_hash {
            return false;
        }

        self.current = self.staging.clone();
        self.current_hash = self.staging_hash;
        self.staging_delta = OracleConfigDelta::default();
        self.staging.epoch = self.current.epoch.wrapping_add(1);
        self.invalidate_staging_cache();
        true
    }

    fn add_node(&mut self, id: NodeID, signer: Signer) -> bool {
        if self.staging.committee.contains_key(&id) {
            return false;
        }

        if let Some(existing) = self.current.committee.get(&id).copied() {
            match self.staging_delta.committee.get(&id) {
                Some(CommitteeChange::Remove(_)) => {
                    self.staging_delta.committee.remove(&id);
                    self.staging.committee.insert(id, existing);
                }
                _ => return false,
            }
        } else {
            match self.staging_delta.committee.entry(id) {
                Entry::Occupied(mut change) => match change.get() {
                    CommitteeChange::Upsert(_) => return false,
                    CommitteeChange::Remove(_) => {
                        *change.get_mut() = CommitteeChange::Upsert(signer);
                    }
                },
                Entry::Vacant(change) => {
                    change.insert(CommitteeChange::Upsert(signer));
                }
            }
            self.staging.committee.insert(id, signer);
        }
        self.invalidate_staging_cache();
        true
    }

    fn remove_node(&mut self, id: NodeID) -> bool {
        if !self.staging.committee.contains_key(&id) {
            return false;
        }

        let existing = self.current.committee.get(&id).copied();
        match self.staging_delta.committee.entry(id) {
            Entry::Occupied(mut change) => match change.get() {
                CommitteeChange::Remove(_) => return false,
                CommitteeChange::Upsert(_) => {
                    if let Some(existing) = existing {
                        *change.get_mut() = CommitteeChange::Remove(existing.id);
                    } else {
                        change.remove();
                    }
                }
            },
            Entry::Vacant(change) => {
                let Some(existing) = existing else {
                    return false;
                };
                change.insert(CommitteeChange::Remove(existing.id));
            }
        }
        self.staging.committee.remove(&id);
        self.invalidate_staging_cache();
        true
    }

    fn set_threshold(&mut self, new_thres: u16) {
        if self.staging.threshold == new_thres {
            return;
        }
        self.staging_delta.threshold = (new_thres != self.current.threshold).then_some(new_thres);
        self.staging.threshold = new_thres;
        self.invalidate_staging_cache();
    }

    pub fn current_config(&self) -> &OracleConfig {
        &self.current
    }

    pub fn current_config_hash(&self) -> &Hash {
        &self.current_hash
    }

    pub fn epoch_advance(&mut self) -> Option<(u32, &OracleConfig, OracleConfigDeltaWire, Hash)> {
        if !self.staging.is_valid() {
            return None;
        }

        self.ensure_staging_cache();
        // FIXME: bootstrap when the committee is empty.
        let config = if self.current.committee.is_empty() {
            &self.staging
        } else {
            &self.current
        };
        Some((
            self.staging.epoch,
            config,
            self.staging_delta_wire.clone(),
            self.staging_hash,
        ))
    }

    pub fn staging_delta(&mut self) -> Option<(u32, &OracleConfig, OracleConfigDeltaWire, Hash)> {
        if self.staging_delta.is_empty() {
            return None;
        }
        self.epoch_advance()
    }

    pub fn validate_epoch_advance(
        &mut self, epoch: u32, config_hash: &Hash, config_delta: &OracleConfigDeltaWire,
    ) -> bool {
        if !self.staging.is_valid() || epoch != self.staging.epoch {
            return false;
        }
        self.ensure_staging_cache();
        if &self.staging_hash != config_hash || &self.staging_delta_wire != config_delta {
            return false;
        }
        true
    }
}

impl OracleSrc {
    pub fn new(topic: &str) -> Self {
        Self {
            topic: topic.to_string(),
            targets: new_hashmap(),
            next_signer_id: 0,
        }
    }

    fn get_oracle_epoch(&self, target: OracleTarget) -> LyquidResult<Option<OracleEpochInfo>> {
        lyquor_api::get_oracle_epoch(self.topic.clone(), target)
    }

    pub fn target_state_mut(&mut self, target: OracleServiceTarget) -> &mut TargetState {
        // TODO: allow this function to directly take OracleTarget (can take different sequence
        // backends).
        let seq_id = lyquor_api::sequence_backend_id().unwrap();
        let target = OracleTarget { target, seq_id };
        self.targets.entry(target).or_insert_with(|| {
            let mut state = TargetState::new(&target);
            let info = lyquor_api::get_oracle_epoch(self.topic.clone(), target);
            if let Ok(Some(target_state)) = info {
                state.on_epoch_update(target_state);
            }
            state
        })
    }

    fn target_state(&self, target: OracleServiceTarget) -> Option<&TargetState> {
        // TODO: allow this function to directly take OracleTarget (can take different sequence
        // backends).
        let seq_id = lyquor_api::sequence_backend_id().unwrap();
        let target = OracleTarget { target, seq_id };
        self.targets.get(&target)
    }

    pub fn sync_targets(&mut self) {
        let keys = self.targets.keys().copied().collect::<Vec<_>>();
        for target in keys {
            if let Ok(Some(target_state)) = self.get_oracle_epoch(target) {
                if let Some(state) = self.targets.get_mut(&target) {
                    state.on_epoch_update(target_state);
                }
            }
        }
    }

    fn add_node(&mut self, target: OracleServiceTarget, id: NodeID) -> bool {
        let key_lvm = id.0;
        let key_evm = match target {
            OracleServiceTarget::LVM(_) => Address::ZERO,
            OracleServiceTarget::EVM { .. } => match lyquor_api::get_ed25519_address(key_lvm).ok().flatten() {
                Some(addr) => addr,
                None => return false,
            },
        };
        let sid = self.next_signer_id;
        self.next_signer_id = self.next_signer_id.wrapping_add(1);
        let signer = Signer {
            id: sid,
            key_lvm,
            key_evm,
        };
        self.target_state_mut(target).add_node(id, signer)
    }

    fn remove_node(&mut self, target: OracleServiceTarget, id: NodeID) -> bool {
        self.target_state_mut(target).remove_node(id)
    }

    fn set_threshold(&mut self, target: OracleServiceTarget, new_thres: u16) {
        self.target_state_mut(target).set_threshold(new_thres);
    }

    pub fn validate_epoch_advance(
        &mut self, target: OracleServiceTarget, topic: &str, epoch: u32, config_hash: &Hash,
        config_delta: &OracleConfigDeltaWire,
    ) -> bool {
        if self.topic != topic {
            return false;
        }
        self.target_state_mut(target)
            .validate_epoch_advance(epoch, config_hash, config_delta)
    }
}

/// Per-topic API wrapper for source-side certified call generation.
#[derive(Clone)]
pub struct SrcWrapper<'a> {
    topic: &'a str,
}

impl<'b> SrcWrapper<'b> {
    pub fn new(topic: &'b str) -> Self {
        Self { topic }
    }

    pub fn topic(&self) -> &str {
        self.topic
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&self, ctx: &mut impl OracleSrcStateContext, target: OracleServiceTarget, id: NodeID) -> bool {
        ctx.instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .add_node(target, id)
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node(&self, ctx: &mut impl OracleSrcStateContext, target: OracleServiceTarget, id: NodeID) -> bool {
        ctx.instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .remove_node(target, id)
    }

    /// Get the currently active oracle config.
    pub fn config_current<'a>(
        &self, ctx: &'a impl OracleSrcReadContext, target: OracleServiceTarget,
    ) -> &'a OracleConfig {
        match ctx
            .instance_internal_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.target_state(target))
        {
            Some(state) => &state.current,
            None => OracleConfig::empty(),
        }
    }

    /// Get the staged oracle config (`current + staging_delta`).
    pub fn config_staging<'a>(
        &self, ctx: &'a impl OracleSrcReadContext, target: OracleServiceTarget,
    ) -> &'a OracleConfig {
        match ctx
            .instance_internal_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.target_state(target))
        {
            Some(state) => &state.staging,
            None => OracleConfig::empty(),
        }
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold(&self, ctx: &mut impl OracleSrcStateContext, target: OracleServiceTarget, new_thres: u16) {
        ctx.instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .set_threshold(target, new_thres);
    }
}
