//! Source-side staged oracle state and wrapper APIs.

use super::*;
use lyquor_primitives::oracle::{
    OracleConfig as OracleConfigWire, OracleConfigDelta as OracleConfigDeltaWire, OracleEpochInfo, OracleSigner, eth,
};
use lyquor_primitives::{Address, Bytes, Cipher, Hash};
use serde::{Deserialize, Serialize};

const MAX_STAGING_OPS: usize = 1024;

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
enum OracleConfigOp {
    AddNode(NodeID, Signer),
    RemoveNode(NodeID),
    SetThreshold(u16),
}

#[derive(Clone)]
pub struct TargetState {
    cipher: Cipher,
    current: OracleConfig,
    current_hash: Hash,
    staging: OracleConfig,
    staging_ops: Vec<OracleConfigOp>,
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

fn apply_config_op(config: &mut OracleConfig, op: &OracleConfigOp) -> bool {
    match op {
        OracleConfigOp::AddNode(id, signer) => {
            if config.committee.contains_key(id) {
                return false;
            }
            config.committee.insert(*id, *signer);
            true
        }
        OracleConfigOp::RemoveNode(id) => config.committee.remove(id).is_some(),
        OracleConfigOp::SetThreshold(threshold) => {
            config.threshold = *threshold;
            true
        }
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
        Self {
            cipher,
            current,
            current_hash: Hash::from_bytes([0; 32]),
            staging_ops: Vec::new(),
            staging,
        }
    }

    #[inline]
    pub(crate) fn materialize_prefix(&self, change_count: u32) -> Option<(OracleConfig, OracleConfigDeltaWire, Hash)> {
        let change_count = usize::try_from(change_count).ok()?;
        if change_count > self.staging_ops.len() {
            return None;
        }

        let mut changes: HashMap<NodeID, Option<Signer>> = new_hashmap();
        let mut threshold = self.current.threshold;
        for op in self.staging_ops.iter().take(change_count) {
            match op {
                OracleConfigOp::AddNode(id, signer) => match (self.current.committee.get(id), changes.get(id)) {
                    (Some(current_signer), Some(None)) => {
                        if current_signer == signer {
                            changes.remove(id);
                        } else {
                            changes.insert(*id, Some(*signer));
                        }
                    }
                    (Some(_), _) | (None, Some(Some(_))) => return None,
                    (None, Some(None)) => {
                        changes.insert(*id, Some(*signer));
                    }
                    (None, None) => {
                        changes.insert(*id, Some(*signer));
                    }
                },
                OracleConfigOp::RemoveNode(id) => match (self.current.committee.get(id), changes.get(id)) {
                    (Some(_), Some(None)) | (None, None) | (None, Some(None)) => return None,
                    (Some(_), _) => {
                        changes.insert(*id, None);
                    }
                    (None, Some(Some(_))) => {
                        changes.remove(id);
                    }
                },
                OracleConfigOp::SetThreshold(new_threshold) => {
                    threshold = *new_threshold;
                }
            }
        }

        let mut committee = new_hashmap();
        let mut upsert = Vec::new();
        let mut remove = Vec::new();
        for (id, current_signer) in self.current.committee.iter() {
            match changes.get(id) {
                Some(Some(next_signer)) => {
                    committee.insert(*id, *next_signer);
                }
                Some(None) => remove.push(current_signer.id),
                None => {
                    committee.insert(*id, *current_signer);
                }
            }
        }
        for (id, signer) in changes.iter() {
            match signer {
                Some(signer) => {
                    if !self.current.committee.contains_key(id) {
                        committee.insert(*id, *signer);
                    } else {
                        remove.push(self.current.committee[id].id);
                    }
                    upsert.push(signer.to_wire(self.cipher));
                }
                None => {}
            }
        }
        upsert.sort_by_key(|signer| signer.id);
        remove.sort();

        let next = OracleConfig {
            committee,
            threshold,
            epoch: self.current.epoch.wrapping_add(1),
        };

        let delta = OracleConfigDeltaWire {
            upsert,
            remove,
            threshold: (threshold != self.current.threshold).then_some(threshold),
        };
        let hash = config_hash(&next, self.cipher);
        Some((next, delta, hash))
    }

    fn push_op(&mut self, op: OracleConfigOp) -> bool {
        if self.staging_ops.len() >= MAX_STAGING_OPS {
            return false;
        }
        if !apply_config_op(&mut self.staging, &op) {
            return false;
        }
        self.staging_ops.push(op);
        true
    }

    fn add_node(&mut self, id: NodeID, signer: Signer) -> bool {
        if self.staging.committee.contains_key(&id) {
            return false;
        }
        let signer = self.current.committee.get(&id).copied().unwrap_or(signer);
        self.push_op(OracleConfigOp::AddNode(id, signer))
    }

    fn remove_node(&mut self, id: NodeID) -> bool {
        if !self.staging.committee.contains_key(&id) {
            return false;
        }
        self.push_op(OracleConfigOp::RemoveNode(id))
    }

    fn set_threshold(&mut self, new_thres: u16) -> bool {
        if self.staging.threshold == new_thres {
            return false;
        }
        self.push_op(OracleConfigOp::SetThreshold(new_thres))
    }

    pub fn current_config(&self) -> &OracleConfig {
        &self.current
    }

    pub fn current_config_hash(&self) -> Hash {
        self.current_hash
    }

    pub fn get_epoch(&self) -> u32 {
        self.current.epoch
    }

    pub fn propose_advance_epoch(&self) -> Option<(u32, &OracleConfig, OracleConfigDeltaWire, Hash, u32)> {
        if !self.staging.is_valid() {
            return None;
        }
        let change_count = u32::try_from(self.staging_ops.len()).ok()?;
        let (_, delta, config_hash) = self.materialize_prefix(change_count)?;
        // FIXME: Bootstrap under the staged config because there is no active committee yet.
        let config = if self.current.committee.is_empty() {
            &self.staging
        } else {
            &self.current
        };
        Some((self.staging.epoch, config, delta, config_hash, change_count))
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

    pub fn finalize_epoch(&mut self, target: OracleServiceTarget, target_state: OracleEpochInfo) -> bool {
        let state = self.target_state_mut(target);
        let target_hash: Hash = <[u8; 32]>::from(target_state.config_hash).into();
        if target_state.epoch != state.current.epoch.wrapping_add(1) {
            return false;
        }
        let Some((next_current, _, expected_hash)) = state.materialize_prefix(target_state.change_count) else {
            return false;
        };
        if expected_hash != target_hash {
            return false;
        }
        let trim_len = match usize::try_from(target_state.change_count) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let mut next_staging = next_current.clone();
        next_staging.epoch = next_current.epoch.wrapping_add(1);
        for op in state.staging_ops.iter().skip(trim_len) {
            if !apply_config_op(&mut next_staging, op) {
                return false;
            }
        }
        state.current = next_current;
        state.current_hash = target_hash;
        state.staging_ops.drain(..trim_len);
        state.staging = next_staging;
        true
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

    fn set_threshold(&mut self, target: OracleServiceTarget, new_thres: u16) -> bool {
        self.target_state_mut(target).set_threshold(new_thres)
    }

    pub fn validate_advance_epoch(
        &self, target: OracleServiceTarget, topic: &str, epoch: u32, config_hash: &Hash,
        config_delta: &OracleConfigDeltaWire, change_count: u32,
    ) -> bool {
        if self.topic != topic {
            return false;
        }
        let Some(state) = self.target_state(target) else {
            return false;
        };
        if !state.staging.is_valid() || epoch != state.staging.epoch {
            return false;
        }
        state
            .materialize_prefix(change_count)
            .is_some_and(|(_, expected_delta, expected_hash)| {
                &expected_delta == config_delta && &expected_hash == config_hash
            })
    }

    pub fn validate_finalize_epoch(&self, target: OracleTarget, target_state: &OracleEpochInfo) -> bool {
        let payload_hash: Hash = <[u8; 32]>::from(target_state.config_hash).into();
        fetch_target_epoch_info(self.topic.as_str(), target, false)
            .ok()
            .flatten()
            .is_some_and(|observed| {
                let observed_hash = Hash::from(<[u8; 32]>::from(observed.config_hash));
                observed.epoch == target_state.epoch &&
                    observed_hash == payload_hash &&
                    observed.change_count == target_state.change_count
            })
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
            .oracle_src_mut(self.topic())
            .add_node(target, id)
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node<T>(&self, _ctx: &mut T, target: OracleServiceTarget, id: NodeID) -> bool {
        crate::runtime::internal::builtin_network_state()
            .oracle_src_mut(self.topic())
            .remove_node(target, id)
    }

    /// Get the currently active oracle config.
    pub fn config_current<T>(&self, _ctx: &T, target: OracleServiceTarget) -> &OracleConfig {
        match crate::runtime::internal::builtin_network_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.target_state(target))
        {
            Some(state) => &state.current,
            None => OracleConfig::empty(),
        }
    }

    /// Get the staged oracle config after applying all queued source-side ops.
    pub fn config_staging<T>(&self, _ctx: &T, target: OracleServiceTarget) -> &OracleConfig {
        match crate::runtime::internal::builtin_network_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.target_state(target))
        {
            Some(state) => &state.staging,
            None => OracleConfig::empty(),
        }
    }

    pub fn get_epoch<T>(&self, _ctx: &T, target: OracleServiceTarget) -> u32 {
        crate::runtime::internal::builtin_network_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.target_state(target))
            .map_or(0, TargetState::get_epoch)
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold<T>(&self, _ctx: &mut T, target: OracleServiceTarget, new_thres: u16) -> bool {
        crate::runtime::internal::builtin_network_state()
            .oracle_src_mut(self.topic())
            .set_threshold(target, new_thres)
    }
}
