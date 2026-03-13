//! Source-side staged oracle state and wrapper APIs.

use super::*;
use hashbrown::hash_map::Entry;
use lyquor_primitives::oracle::{
    OracleConfig as OracleConfigWire, OracleConfigDelta as OracleConfigDeltaWire, OracleEpochInfo, OracleSigner, eth,
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

    fn from_wire(config: &OracleConfigWire, cipher: Cipher, epoch: u32) -> Option<Self> {
        let mut committee = new_hashmap();
        for signer in config.committee.iter() {
            let (node_id, key_lvm, key_evm) = match cipher {
                Cipher::Ed25519 => {
                    let key_lvm: [u8; 32] = signer.key.as_ref().try_into().ok()?;
                    let key_evm = lyquor_api::get_address_by_ed25519(key_lvm)
                        .ok()
                        .flatten()
                        .unwrap_or(Address::ZERO);
                    (NodeID::from(key_lvm), key_lvm, key_evm)
                }
                Cipher::Secp256k1 => {
                    let key_evm = Address::from_slice(signer.key.as_ref());
                    let node_id = lyquor_api::get_ed25519_by_address(key_evm).ok().flatten()?;
                    (node_id, node_id.0, key_evm)
                }
            };
            if committee
                .insert(
                    node_id,
                    Signer {
                        id: signer.id,
                        key_lvm,
                        key_evm,
                    },
                )
                .is_some()
            {
                return None;
            }
        }
        Some(Self {
            committee,
            threshold: config.threshold,
            epoch,
        })
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
        }
    }

    #[inline]
    fn staging_config_hash(&self) -> Hash {
        config_hash(&self.staging, self.cipher)
    }

    #[inline]
    fn staging_delta_wire(&self) -> OracleConfigDeltaWire {
        self.staging_delta.to_wire(self.cipher)
    }

    fn replace_current(&mut self, config: OracleConfig) {
        self.current = config;
        self.staging_delta = OracleConfigDelta::default();
        self.staging = self.current.clone();
        self.staging.epoch = self.current.epoch.wrapping_add(1);
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
        true
    }

    fn set_threshold(&mut self, new_thres: u16) {
        if self.staging.threshold == new_thres {
            return;
        }
        self.staging_delta.threshold = (new_thres != self.current.threshold).then_some(new_thres);
        self.staging.threshold = new_thres;
    }

    pub fn current_config(&self) -> &OracleConfig {
        &self.current
    }

    pub fn current_config_hash(&self) -> Hash {
        if self.current.epoch == 0 && self.current.threshold == 0 && self.current.committee.is_empty() {
            Hash::from_bytes([0; 32])
        } else {
            config_hash(&self.current, self.cipher)
        }
    }

    pub fn get_epoch(&self) -> u32 {
        self.current.epoch
    }

    pub fn epoch_advance(&self) -> Option<(u32, &OracleConfig, OracleConfigDeltaWire, Hash)> {
        if !self.staging.is_valid() {
            return None;
        }
        // Bootstrap under the staged config because there is no active committee yet.
        let config = if self.current.committee.is_empty() {
            &self.staging
        } else {
            &self.current
        };
        Some((
            self.staging.epoch,
            config,
            self.staging_delta_wire(),
            self.staging_config_hash(),
        ))
    }

    pub fn epoch_finalize_vote(&self, use_staging: bool) -> Option<(u32, &OracleConfig, Hash)> {
        let (epoch, config, hash) = if use_staging {
            (self.staging.epoch, &self.staging, self.staging_config_hash())
        } else {
            (self.current.epoch, &self.current, self.current_config_hash())
        };
        config.is_valid().then_some((epoch, config, hash))
    }

    pub fn validate_epoch_advance(&self, epoch: u32, config_hash: &Hash, config_delta: &OracleConfigDeltaWire) -> bool {
        if !self.staging.is_valid() || epoch != self.staging.epoch {
            return false;
        }
        if &self.staging_config_hash() != config_hash || &self.staging_delta_wire() != config_delta {
            return false;
        }
        true
    }

    fn apply_epoch_finalize(&mut self, target_state: OracleEpochInfo) -> bool {
        let target_hash: Hash = <[u8; 32]>::from(target_state.config_hash).into();
        if target_state.epoch == self.current.epoch && target_hash == self.current_config_hash() {
            return false;
        }
        match target_state.config {
            Some(config_wire) => {
                let actual_hash = match self.cipher {
                    Cipher::Ed25519 => config_wire.to_hash(),
                    Cipher::Secp256k1 => eth::OracleConfig::from(config_wire.clone()).to_hash(),
                };
                if actual_hash != target_hash {
                    return false;
                }
                let Some(config) = OracleConfig::from_wire(&config_wire, self.cipher, target_state.epoch) else {
                    return false;
                };
                self.replace_current(config);
            }
            None => {
                if target_state.epoch != 0 || target_hash != Hash::from_bytes([0; 32]) {
                    return false;
                }
                self.replace_current(OracleConfig::new());
            }
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

    pub fn target_state_mut(&mut self, target: OracleServiceTarget) -> &mut TargetState {
        let seq_id = lyquor_api::sequence_backend_id().unwrap();
        let target = OracleTarget { target, seq_id };
        self.targets.entry(target).or_insert_with(|| TargetState::new(&target))
    }

    pub fn target_state(&self, target: OracleServiceTarget) -> Option<&TargetState> {
        let seq_id = lyquor_api::sequence_backend_id().unwrap();
        let target = OracleTarget { target, seq_id };
        self.targets.get(&target)
    }

    pub fn validate_epoch_finalize(
        &self, source: LyquidID, target: OracleTarget, epoch: u32, config_hash: &Hash, target_state: &OracleEpochInfo,
    ) -> bool {
        let Some(target_state_local) = self.targets.get(&target) else {
            return false;
        };
        let Some(source_state) = self.target_state(OracleServiceTarget::LVM(source)) else {
            return false;
        };
        let use_staging = target.target == OracleServiceTarget::LVM(source);
        let Some((source_epoch, _, source_hash)) = source_state.epoch_finalize_vote(use_staging) else {
            return false;
        };
        if source_epoch != epoch || &source_hash != config_hash {
            return false;
        }
        let payload_hash: Hash = <[u8; 32]>::from(target_state.config_hash).into();
        let config_ok = match &target_state.config {
            Some(config) => {
                (match target.target {
                    OracleServiceTarget::LVM(_) => config.to_hash(),
                    OracleServiceTarget::EVM { .. } => eth::OracleConfig::from(config.clone()).to_hash(),
                }) == payload_hash
            }
            None => payload_hash == Hash::from_bytes([0; 32]),
        };
        config_ok &&
            fetch_target_epoch_info(self.topic.as_str(), target, false)
                .ok()
                .flatten()
                .is_some_and(|observed| {
                    let observed_hash = Hash::from(<[u8; 32]>::from(observed.config_hash));
                    observed.epoch == target_state.epoch &&
                        observed_hash == payload_hash &&
                        (observed.epoch != target_state_local.current.epoch ||
                            observed_hash != target_state_local.current_config_hash())
                })
    }

    pub fn finalize_epoch(&mut self, target: OracleServiceTarget, target_state: OracleEpochInfo) -> bool {
        self.target_state_mut(target).apply_epoch_finalize(target_state)
    }

    fn add_node(&mut self, target: OracleServiceTarget, id: NodeID) -> bool {
        let key_lvm = id.0;
        let key_evm = match target {
            OracleServiceTarget::LVM(_) => Address::ZERO,
            OracleServiceTarget::EVM { .. } => match lyquor_api::get_address_by_ed25519(key_lvm).ok().flatten() {
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
        &self, target: OracleServiceTarget, topic: &str, epoch: u32, config_hash: &Hash,
        config_delta: &OracleConfigDeltaWire,
    ) -> bool {
        if self.topic != topic {
            return false;
        }
        self.target_state(target)
            .is_some_and(|state| state.validate_epoch_advance(epoch, config_hash, config_delta))
    }
}

/// Per-topic API wrapper for source-side certified call generation.
#[derive(Clone)]
pub struct StateVar<'a> {
    topic: &'a str,
}

impl<'b> StateVar<'b> {
    pub fn new(topic: &'b str) -> Self {
        Self { topic }
    }

    pub fn topic(&self) -> &str {
        self.topic
    }

    /// Add a node to the committee. If the node exists, returns false.
    pub fn add_node<T>(&self, _ctx: &mut T, target: OracleServiceTarget, id: NodeID) -> bool {
        crate::runtime::internal::builtin_network_state()
            .expect("NEAT: failed to access builtin network state.")
            .oracle_src_mut(self.topic())
            .add_node(target, id)
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node<T>(&self, _ctx: &mut T, target: OracleServiceTarget, id: NodeID) -> bool {
        crate::runtime::internal::builtin_network_state()
            .expect("NEAT: failed to access builtin network state.")
            .oracle_src_mut(self.topic())
            .remove_node(target, id)
    }

    /// Get the currently active oracle config.
    pub fn config_current<T>(&self, _ctx: &T, target: OracleServiceTarget) -> &OracleConfig {
        match crate::runtime::internal::builtin_network_state()
            .expect("NEAT: failed to access builtin network state.")
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.target_state(target))
        {
            Some(state) => &state.current,
            None => OracleConfig::empty(),
        }
    }

    /// Get the staged oracle config (`current + staging_delta`).
    pub fn config_staging<T>(&self, _ctx: &T, target: OracleServiceTarget) -> &OracleConfig {
        match crate::runtime::internal::builtin_network_state()
            .expect("NEAT: failed to access builtin network state.")
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.target_state(target))
        {
            Some(state) => &state.staging,
            None => OracleConfig::empty(),
        }
    }

    pub fn get_epoch<T>(&self, _ctx: &T, target: OracleServiceTarget) -> u32 {
        crate::runtime::internal::builtin_network_state()
            .expect("NEAT: failed to access builtin network state.")
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.target_state(target))
            .map_or(0, TargetState::get_epoch)
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold<T>(&self, _ctx: &mut T, target: OracleServiceTarget, new_thres: u16) {
        crate::runtime::internal::builtin_network_state()
            .expect("NEAT: failed to access builtin network state.")
            .oracle_src_mut(self.topic())
            .set_threshold(target, new_thres);
    }
}
