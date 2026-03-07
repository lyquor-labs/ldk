//! Source-side local oracle cache and Source wrapper APIs.
//!
//! This cache is not authoritative consensus state. It is a local view used to drive Source
//! voting/certification liveness before Target-side verification.

use super::*;
use lyquor_primitives::oracle::{
    OracleConfig as OracleConfigWire, OracleConfigDelta as OracleConfigDeltaWire, OracleSigner, eth,
};
use lyquor_primitives::{Address, Bytes, Cipher, Hash};
use serde::{Deserialize, Serialize};

pub fn oracle_target_evm_from_address(target: Address) -> LyquidResult<OracleTarget> {
    if target == Address::ZERO {
        return Err(LyquidError::LyquorRuntime("EVM target address cannot be zero.".into()));
    }
    let seq_id = lyquor_api::sequence_backend_id()?;
    let Some(eth_contract) = lyquor_api::eth_contract()? else {
        return Err(LyquidError::LyquorRuntime(
            "EVM target requires eth contract address.".into(),
        ));
    };
    Ok(OracleTarget {
        target: OracleServiceTarget::EVM { target, eth_contract },
        seq_id,
    })
}

pub fn oracle_target_lvm_from_address(lyquid_id: LyquidID, target: Address) -> LyquidResult<OracleTarget> {
    let seq_id = lyquor_api::sequence_backend_id()?;
    let target = if target == Address::ZERO {
        lyquid_id
    } else {
        target.into()
    };
    Ok(OracleTarget {
        target: OracleServiceTarget::LVM(target),
        seq_id,
    })
}

pub(super) fn get_config<'a>(
    cert_epoch: u32, current: &'a OracleConfig, staging: &'a OracleConfig,
) -> Option<&'a OracleConfig> {
    if cert_epoch != current.epoch.wrapping_add(1) || current == staging {
        return None;
    }
    if current.is_valid() {
        Some(current)
    } else if staging.is_valid() {
        // Bootstrap: before the first landed epoch update, voting uses staged config.
        Some(staging)
    } else {
        None
    }
}

#[inline]
fn empty_oracle_config() -> &'static OracleConfig {
    static EMPTY: std::sync::OnceLock<OracleConfig> = std::sync::OnceLock::new();
    EMPTY.get_or_init(OracleConfig::new)
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signer {
    pub id: SignerID,
    pub key_lvm: [u8; 32], // ed25519 native key
    pub key_evm: Address,  // Secp256k1 signer's address
}

impl Signer {
    /// Return the key/address that is used for verification.
    pub(super) fn get_verifying_key(&self, cipher: Cipher) -> Bytes {
        match cipher {
            Cipher::Ed25519 => Bytes::copy_from_slice(&self.key_lvm),
            Cipher::Secp256k1 => Bytes::copy_from_slice(self.key_evm.as_ref()),
        }
    }

    /// Get the wire format for a platform, determined by `cipher`.
    pub(super) fn to_wire(&self, cipher: Cipher) -> OracleSigner {
        OracleSigner {
            id: self.id,
            key: self.get_verifying_key(cipher),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct OracleConfig {
    pub committee: HashMap<NodeID, Signer>,
    pub threshold: u16,
    pub epoch: u32,
}

impl OracleConfig {
    pub(super) fn new() -> Self {
        Self {
            committee: new_hashmap(),
            threshold: 0,
            epoch: 0,
        }
    }

    #[inline]
    pub(super) fn is_valid(&self) -> bool {
        self.threshold != 0 &&
            self.committee.len() <= u16::MAX as usize &&
            self.committee.len() >= self.threshold as usize
    }

    pub(super) fn get_oracle_config_wire(&self, cipher: Cipher) -> OracleConfigWire {
        let mut committee: Vec<_> = self.committee.iter().map(|(_, s)| s.to_wire(cipher)).collect();
        // The canonical representation of a committee set is sorted by nodes' IDs.
        committee.sort_by_key(|s| s.id);
        OracleConfigWire {
            committee,
            threshold: self.threshold,
        }
    }

    pub(super) fn apply_staging_delta(&self, delta: &OracleStagingDelta) -> Self {
        let mut out = self.clone();
        for (node, change) in delta.committee.iter() {
            match change {
                OracleStagingCommitteeChange::Upsert(signer) => {
                    out.committee.insert(*node, *signer);
                }
                OracleStagingCommitteeChange::Remove(_) => {
                    out.committee.remove(node);
                }
            }
        }
        if let Some(threshold) = delta.threshold {
            out.threshold = threshold;
        }
        out
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum OracleStagingCommitteeChange {
    Upsert(Signer),
    Remove(SignerID),
}

#[derive(Clone, PartialEq, Eq, Default)]
pub(super) struct OracleStagingDelta {
    committee: HashMap<NodeID, OracleStagingCommitteeChange>,
    threshold: Option<u16>,
}

impl OracleStagingDelta {
    pub(super) fn is_empty(&self) -> bool {
        self.committee.is_empty() && self.threshold.is_none()
    }

    pub(super) fn to_wire(&self, cipher: Cipher) -> OracleConfigDeltaWire {
        let mut upsert = Vec::new();
        let mut remove = Vec::new();
        for (_node, op) in self.committee.iter() {
            match op {
                OracleStagingCommitteeChange::Upsert(signer) => {
                    upsert.push(signer.to_wire(cipher));
                }
                OracleStagingCommitteeChange::Remove(id) => remove.push(*id),
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

    pub(super) fn from_configs(current: &OracleConfig, staged: &OracleConfig) -> Self {
        let mut committee = new_hashmap();
        for (node, curr) in current.committee.iter() {
            match staged.committee.get(node) {
                Some(staged_signer) if staged_signer == curr => {}
                Some(staged_signer) => {
                    committee.insert(*node, OracleStagingCommitteeChange::Upsert(*staged_signer));
                }
                None => {
                    committee.insert(*node, OracleStagingCommitteeChange::Remove(curr.id));
                }
            }
        }
        for (node, staged_signer) in staged.committee.iter() {
            if !current.committee.contains_key(node) {
                committee.insert(*node, OracleStagingCommitteeChange::Upsert(*staged_signer));
            }
        }
        let threshold = (staged.threshold != current.threshold).then_some(staged.threshold);
        Self { committee, threshold }
    }
}

#[derive(Clone)]
pub(super) struct OracleTargetState {
    pub(super) cipher: Cipher,
    pub(super) current: OracleConfig,
    pub(super) staging_delta: OracleStagingDelta,
    pub(super) staging: OracleConfig,
    pub(super) pending: Option<PendingEpochAdvance>,
    pub(super) current_hash: Hash,
    pub(super) staging_hash: Hash,
    pub(super) staging_delta_wire: OracleConfigDeltaWire,
    pub(super) staging_cache_dirty: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub(super) enum OracleStateKey {
    LVM(LyquidID),
    EVM(Address),
}

#[doc(hidden)]
pub struct OracleSrc {
    topic: String,
    targets: HashMap<OracleStateKey, OracleTargetState>,
    next_signer_id: SignerID,
}

#[derive(Clone)]
pub(super) struct PendingEpochAdvance {
    pub(super) epoch: u32,
    pub(super) delta: OracleStagingDelta,
    pub(super) delta_wire: OracleConfigDeltaWire,
    pub(super) config_hash: Hash,
}

pub(super) fn state_key(target: OracleServiceTarget) -> OracleStateKey {
    match target {
        OracleServiceTarget::LVM(id) => OracleStateKey::LVM(id),
        OracleServiceTarget::EVM { eth_contract, .. } => OracleStateKey::EVM(eth_contract),
    }
}

pub(super) fn state_key_cipher(key: OracleStateKey) -> Cipher {
    match key {
        OracleStateKey::LVM(_) => Cipher::Ed25519,
        OracleStateKey::EVM(_) => Cipher::Secp256k1,
    }
}

pub(super) fn config_hash_for_cipher(config: &OracleConfig, cipher: Cipher) -> Hash {
    match cipher {
        Cipher::Ed25519 => config.get_oracle_config_wire(Cipher::Ed25519).to_hash(),
        Cipher::Secp256k1 => eth::OracleConfig::from(config.get_oracle_config_wire(Cipher::Secp256k1)).to_hash(),
    }
}

impl OracleTargetState {
    pub(super) fn new(key: OracleStateKey) -> Self {
        let cipher = state_key_cipher(key);
        let current = OracleConfig::new();
        let staging = current.clone();
        let staging_delta = OracleStagingDelta::default();
        let mut state = Self {
            cipher,
            current,
            staging_delta,
            staging,
            pending: None,
            current_hash: Hash::from_bytes([0; 32]),
            staging_hash: Hash::from_bytes([0; 32]),
            staging_delta_wire: OracleConfigDeltaWire {
                upsert: Vec::new(),
                remove: Vec::new(),
                threshold: None,
            },
            staging_cache_dirty: false,
        };
        state.refresh_current_cache();
        state.refresh_staging_cache();
        state
    }

    pub(super) fn refresh_current_cache(&mut self) {
        self.current_hash = if self.current.threshold == 0 {
            Hash::from_bytes([0; 32])
        } else {
            config_hash_for_cipher(&self.current, self.cipher)
        };
    }

    pub(super) fn refresh_staging_cache(&mut self) {
        self.staging_hash = config_hash_for_cipher(&self.staging, self.cipher);
        self.staging_delta_wire = self.staging_delta.to_wire(self.cipher);
        self.staging_cache_dirty = false;
    }

    pub(super) fn invalidate_staging_cache(&mut self) {
        self.staging_cache_dirty = true;
    }

    pub(super) fn ensure_staging_cache(&mut self) {
        if self.staging_cache_dirty {
            self.refresh_staging_cache();
        }
    }

    pub(super) fn sync_current_state(&mut self, target_state: OracleEpochInfo) -> bool {
        let target_epoch = target_state.epoch;
        let target_hash = Hash::from_bytes(<[u8; 32]>::from(target_state.config_hash));

        // Ignore stale snapshots.
        if target_epoch < self.current.epoch {
            return false;
        }

        let current_hash = self.current_hash;
        // Same epoch: only hash-consistency check.
        if target_epoch == self.current.epoch {
            return current_hash == target_hash;
        }

        // Preferred path: target confirms the pending next-epoch config.
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.epoch == target_epoch && pending.config_hash == target_hash)
        {
            let pending = self.pending.take().unwrap();
            self.current = self.current.apply_staging_delta(&pending.delta);
            self.current.epoch = target_epoch;
            self.refresh_current_cache();
            self.staging_delta = OracleStagingDelta::from_configs(&self.current, &self.staging);
            self.staging.epoch = target_epoch;
            self.invalidate_staging_cache();
            return true;
        }

        self.ensure_staging_cache();
        let staging_hash = self.staging_hash;
        // Fallback: target hash matches local staged config.
        if staging_hash == target_hash {
            self.current = self.staging.clone();
            self.current.epoch = target_epoch;
            self.pending = None;
            self.staging_delta = OracleStagingDelta::default();
            self.refresh_current_cache();
            self.staging.epoch = target_epoch;
            self.invalidate_staging_cache();
            return true;
        }

        if current_hash != target_hash {
            return false;
        }

        // Epoch advanced without config change.
        self.pending = None;
        self.current.epoch = target_epoch;
        self.staging.epoch = target_epoch;
        true
    }

    pub(super) fn has_node(&self, id: &NodeID) -> bool {
        match self.staging_delta.committee.get(id) {
            Some(OracleStagingCommitteeChange::Upsert(_)) => true,
            Some(OracleStagingCommitteeChange::Remove(_)) => false,
            None => self.current.committee.contains_key(id),
        }
    }

    pub(super) fn add_node(&mut self, id: NodeID, signer: Signer) {
        if self.has_node(&id) {
            return;
        }
        // Removing and re-adding the same signer in one epoch should cancel out the staged remove
        // (instead of keeping a redundant upsert delta).
        if self.current.committee.get(&id).copied().is_some_and(|s| s == signer) {
            self.staging_delta.committee.remove(&id);
            self.staging.committee.insert(id, signer);
            self.invalidate_staging_cache();
            return;
        }
        self.staging_delta
            .committee
            .insert(id, OracleStagingCommitteeChange::Upsert(signer));
        self.staging.committee.insert(id, signer);
        self.invalidate_staging_cache();
    }

    pub(super) fn remove_node(&mut self, id: &NodeID) {
        let current = self.current.committee.get(id).copied();
        let changed = match self.staging_delta.committee.get(id) {
            Some(OracleStagingCommitteeChange::Remove(_)) => false,
            Some(OracleStagingCommitteeChange::Upsert(_)) => {
                match current {
                    Some(curr) => {
                        self.staging_delta
                            .committee
                            .insert(*id, OracleStagingCommitteeChange::Remove(curr.id));
                    }
                    None => {
                        self.staging_delta.committee.remove(id);
                    }
                }
                self.staging.committee.remove(id);
                true
            }
            None => match current {
                Some(curr) => {
                    self.staging_delta
                        .committee
                        .insert(*id, OracleStagingCommitteeChange::Remove(curr.id));
                    self.staging.committee.remove(id);
                    true
                }
                None => false,
            },
        };
        if changed {
            self.invalidate_staging_cache();
        }
    }

    pub(super) fn set_threshold(&mut self, new_thres: u16) {
        if self.staging.threshold == new_thres {
            return;
        }
        self.staging_delta.threshold = (new_thres != self.current.threshold).then_some(new_thres);
        self.staging.threshold = new_thres;
        self.invalidate_staging_cache();
    }

    pub(super) fn epoch_advance_candidate(&mut self) -> Option<(u32, OracleConfig, OracleConfigDeltaWire, Hash)> {
        if let Some(pending) = self.pending.as_ref() {
            return Some((
                pending.epoch,
                self.current.apply_staging_delta(&pending.delta),
                pending.delta_wire.clone(),
                pending.config_hash,
            ));
        }
        if self.staging_delta.is_empty() {
            return None;
        }
        self.ensure_staging_cache();
        Some((
            self.current.epoch.wrapping_add(1),
            self.staging.clone(),
            self.staging_delta_wire.clone(),
            self.staging_hash,
        ))
    }

    pub(super) fn matches_pending(&mut self, epoch: u32, config_hash: &Hash) -> bool {
        if let Some(pending) = self.pending.as_ref() {
            return pending.epoch == epoch && pending.config_hash == *config_hash;
        }
        self.ensure_staging_cache();
        self.staging_hash == *config_hash
    }
}

impl OracleSrc {
    pub(crate) fn new(topic: &str) -> Self {
        Self {
            topic: topic.to_string(),
            targets: new_hashmap(),
            next_signer_id: 0,
        }
    }

    pub(super) fn get_oracle_epoch(&self, target: OracleServiceTarget) -> LyquidResult<Option<OracleEpochInfo>> {
        let seq_id = lyquor_api::sequence_backend_id()?;
        let target = OracleTarget { target, seq_id };
        // Pull destination epoch/config info for initial/manual sync.
        // Regular call certification paths do not query here on the hot path.
        lyquor_api::get_oracle_epoch(self.topic.clone(), target)
    }

    fn get_oracle_epoch_by_target(&self, target: OracleStateKey) -> LyquidResult<Option<OracleEpochInfo>> {
        match target {
            OracleStateKey::LVM(id) => self.get_oracle_epoch(OracleServiceTarget::LVM(id)),
            OracleStateKey::EVM(eth_contract) => {
                // Oracle epoch is keyed by sequencing contract/topic, so destination address does
                // not affect this query.
                self.get_oracle_epoch(OracleServiceTarget::EVM {
                    target: eth_contract,
                    eth_contract,
                })
            }
        }
    }

    pub(super) fn state_by_target(&mut self, target: OracleServiceTarget) -> &mut OracleTargetState {
        let key = state_key(target);
        if !self.targets.contains_key(&key) {
            let mut state = OracleTargetState::new(key);
            if let Ok(Some(target_state)) = self.get_oracle_epoch(target) {
                state.sync_current_state(target_state);
            }
            self.targets.insert(key, state);
        }
        // key is ensured to exist above.
        self.targets.get_mut(&key).unwrap()
    }

    pub(super) fn state_by_target_ref(&self, target: OracleServiceTarget) -> Option<&OracleTargetState> {
        let key = state_key(target);
        self.targets.get(&key)
    }

    pub(crate) fn sync_known_targets_on_load(&mut self) {
        let keys = self.targets.keys().copied().collect::<Vec<_>>();
        for key in keys {
            if let Ok(Some(target_state)) = self.get_oracle_epoch_by_target(key) {
                if let Some(state) = self.targets.get_mut(&key) {
                    state.sync_current_state(target_state);
                }
            }
        }
    }

    pub fn sync_current_state_with_info(&mut self, target: OracleServiceTarget, target_state: OracleEpochInfo) -> bool {
        let key = state_key(target);
        let state = self.targets.entry(key).or_insert_with(|| OracleTargetState::new(key));
        state.sync_current_state(target_state)
    }

    fn add_node(&mut self, target: OracleServiceTarget, id: NodeID) -> bool {
        let (has_node, existing_id) = {
            let state = self.state_by_target(target);
            let has_node = state.has_node(&id);
            let existing_id = state.current.committee.get(&id).map(|s| s.id);
            (has_node, existing_id)
        };
        if has_node {
            return false;
        }
        let key_lvm = id.0;
        let key_evm = match target {
            OracleServiceTarget::LVM(_) => Address::ZERO,
            OracleServiceTarget::EVM { .. } => match lyquor_api::get_ed25519_address(key_lvm).ok().flatten() {
                Some(addr) => addr,
                None => return false,
            },
        };
        let sid = match existing_id {
            Some(id) => id,
            None => {
                let sid = self.next_signer_id;
                self.next_signer_id = self.next_signer_id.wrapping_add(1);
                sid
            }
        };
        let signer = Signer {
            id: sid,
            key_lvm,
            key_evm,
        };
        self.state_by_target(target).add_node(id, signer);
        true
    }

    fn remove_node(&mut self, target: OracleServiceTarget, id: &NodeID) -> bool {
        let state = self.state_by_target(target);
        if !state.has_node(id) {
            return false;
        }
        state.remove_node(id);
        true
    }

    fn set_threshold(&mut self, target: OracleServiceTarget, new_thres: u16) {
        self.state_by_target(target).set_threshold(new_thres);
    }
}

/// Per-topic API wrapper for source-side certified call generation.
#[derive(Clone)]
pub struct SrcWrapper {
    topic: String,
}

impl SrcWrapper {
    pub fn new(topic: &str) -> Self {
        Self {
            topic: topic.to_string(),
        }
    }

    pub(super) fn topic(&self) -> &str {
        self.topic.as_str()
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node(&self, ctx: &mut impl OracleSrcStateContext, target: OracleServiceTarget, id: NodeID) -> bool {
        ctx.instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .add_node(target, id)
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node(&self, ctx: &mut impl OracleSrcStateContext, target: OracleServiceTarget, id: &NodeID) -> bool {
        ctx.instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .remove_node(target, id)
    }

    /// Get the currently active oracle config.
    pub fn config_current<'a>(
        &self, ctx: &'a impl OracleSrcReadContext, target: OracleServiceTarget,
    ) -> &'a OracleConfig {
        if let Some(state) = ctx
            .instance_internal_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.state_by_target_ref(target))
        {
            &state.current
        } else {
            empty_oracle_config()
        }
    }

    /// Get the staged oracle config (`current + staging_delta`).
    pub fn config_staging<'a>(
        &self, ctx: &'a impl OracleSrcReadContext, target: OracleServiceTarget,
    ) -> &'a OracleConfig {
        if let Some(state) = ctx
            .instance_internal_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.state_by_target_ref(target))
        {
            &state.staging
        } else {
            empty_oracle_config()
        }
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold(&self, ctx: &mut impl OracleSrcStateContext, target: OracleServiceTarget, new_thres: u16) {
        ctx.instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .set_threshold(target, new_thres);
    }

    /// Sync local current state from the destination backend's epoch/config state.
    pub fn sync_current_state(&self, ctx: &mut impl OracleSrcStateContext, target: OracleTarget) -> bool {
        // Pull once from destination backend, then reconcile local per-target cache.
        let target_state = match lyquor_api::get_oracle_epoch(self.topic.clone(), target) {
            Ok(Some(v)) => v,
            _ => return false,
        };
        ctx.instance_internal_state_mut()
            .oracle_src_mut(self.topic())
            .state_by_target(target.target)
            .sync_current_state(target_state)
    }
}
