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
    fn new(node_id: NodeID, next_signer_id: SignerID, cipher: Cipher) -> Option<Self> {
        let key_lvm = node_id.0;
        let key_evm = match cipher {
            Cipher::Ed25519 => Address::ZERO,
            Cipher::Secp256k1 => lyquor_api::get_address_by_ed25519(key_lvm).ok().flatten()?,
        };
        Some(Self {
            id: next_signer_id,
            key_lvm,
            key_evm,
        })
    }

    /// Return the key/address that is used for verification.
    pub fn get_verifying_key(&self, cipher: Cipher) -> Bytes {
        match cipher {
            Cipher::Ed25519 => Bytes::copy_from_slice(&self.key_lvm),
            Cipher::Secp256k1 => Bytes::copy_from_slice(self.key_evm.as_ref()),
        }
    }

    /// Get the wire format for a platform, determined by `cipher`.
    pub fn to_wire(&self, cipher: Cipher) -> OracleSigner {
        let key = match cipher {
            Cipher::Ed25519 => Bytes::copy_from_slice(&self.key_lvm),
            Cipher::Secp256k1 => Bytes::copy_from_slice(&self.key_lvm),
        };
        OracleSigner { id: self.id, key }
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

    pub fn to_hash(&self, cipher: Cipher) -> Hash {
        match cipher {
            Cipher::Ed25519 => self.to_wire(Cipher::Ed25519).to_hash(),
            Cipher::Secp256k1 => eth::OracleConfig::from(self.to_wire(Cipher::Secp256k1)).to_hash(),
        }
    }

    fn apply_op(&mut self, op: &OracleConfigOp) -> bool {
        match op {
            OracleConfigOp::AddNode(id, signer) => {
                if self.committee.contains_key(id) {
                    return false;
                }
                self.committee.insert(*id, *signer);
                true
            }
            OracleConfigOp::RemoveNode(id) => self.committee.remove(id).is_some(),
            OracleConfigOp::SetThreshold(threshold) => {
                self.threshold = *threshold;
                true
            }
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
pub struct SourceState {
    cipher: Cipher,
    current: OracleConfig,
    current_hash: Hash,
    staging: OracleConfig,
    staging_ops: Vec<OracleConfigOp>,
}

pub struct OracleSrc {
    topic: String,
    states: HashMap<OracleTarget, SourceState>,
    next_signer_id: SignerID,
}

impl SourceState {
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

    pub fn materialize_prefix(&self, change_count: u32) -> Option<(OracleConfig, OracleConfigDeltaWire)> {
        if change_count > self.staging_ops.len() as u32 {
            return None;
        }
        let change_count = change_count as usize;

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
                    (None, _) => {
                        changes.insert(*id, Some(*signer));
                    }
                    _ => return None,
                },
                OracleConfigOp::RemoveNode(id) => match (self.current.committee.get(id), changes.get(id)) {
                    (Some(_), _) => {
                        changes.insert(*id, None);
                    }
                    (None, Some(Some(_))) => {
                        changes.remove(id);
                    }
                    _ => return None,
                },
                OracleConfigOp::SetThreshold(new_threshold) => {
                    threshold = *new_threshold;
                }
            }
        }

        let mut committee = self.current.committee.clone();
        let mut upsert = Vec::new();
        let mut remove = Vec::new();
        for (id, signer) in changes {
            match signer {
                Some(signer) => {
                    upsert.push(signer.to_wire(self.cipher));
                    committee.insert(id, signer);
                }
                None => {
                    let current_signer = self.current.committee.get(&id)?;
                    remove.push(current_signer.id);
                    committee.remove(&id);
                }
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
        Some((next, delta))
    }

    fn push_op(&mut self, op: OracleConfigOp) -> bool {
        if self.staging_ops.len() >= MAX_STAGING_OPS {
            return false;
        }
        if !self.staging.apply_op(&op) {
            return false;
        }
        self.staging_ops.push(op);
        true
    }

    fn add_node(&mut self, id: NodeID, next_signer_id: SignerID) -> bool {
        if self.current.epoch == 0 {
            return false;
        }
        if self.staging.committee.contains_key(&id) {
            return false;
        }
        let signer = match self.current.committee.get(&id).copied() {
            Some(signer) => signer,
            None => match Signer::new(id, next_signer_id, self.cipher) {
                Some(signer) => signer,
                None => return false,
            },
        };
        self.push_op(OracleConfigOp::AddNode(id, signer))
    }

    fn remove_node(&mut self, id: NodeID) -> bool {
        if self.current.epoch == 0 {
            return false;
        }
        if !self.staging.committee.contains_key(&id) {
            return false;
        }
        self.push_op(OracleConfigOp::RemoveNode(id))
    }

    fn set_threshold(&mut self, new_thres: u16) -> bool {
        if self.current.epoch == 0 {
            return false;
        }
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
}

impl OracleSrc {
    pub fn new(topic: &str) -> Self {
        Self {
            topic: topic.to_string(),
            states: new_hashmap(),
            next_signer_id: 0,
        }
    }

    #[inline(always)]
    fn source_state_mut(&mut self, target: OracleTarget) -> &mut SourceState {
        self.states.entry(target).or_insert_with(|| SourceState::new(&target))
    }

    #[inline(always)]
    pub fn source_state(&self, target: OracleTarget) -> Option<&SourceState> {
        self.states.get(&target)
    }

    pub fn initialize(&mut self, target: OracleTarget, committee: Vec<NodeID>, threshold: u16) -> bool {
        if let Some(state) = self.states.get(&target) {
            if state.current.epoch != 0 {
                return false;
            }
        }

        let mut next_signer_id = self.next_signer_id;
        let mut state = SourceState::new(&target);
        for id in committee {
            let signer = match Signer::new(id, next_signer_id, state.cipher) {
                Some(signer) => signer,
                None => return false,
            };
            if !state.push_op(OracleConfigOp::AddNode(id, signer)) {
                return false;
            }
            next_signer_id = next_signer_id.wrapping_add(1);
        }
        if !state.push_op(OracleConfigOp::SetThreshold(threshold)) {
            return false;
        }
        if !state.staging.is_valid() {
            return false;
        }

        self.next_signer_id = next_signer_id;
        self.states.insert(target, state);
        true
    }

    fn add_node(&mut self, target: OracleTarget, id: NodeID) -> bool {
        let Some(state) = self.states.get_mut(&target) else {
            return false;
        };
        if !state.add_node(id, self.next_signer_id) {
            return false;
        }
        self.next_signer_id = self.next_signer_id.wrapping_add(1);
        true
    }

    fn remove_node(&mut self, target: OracleTarget, id: NodeID) -> bool {
        self.states.get_mut(&target).is_some_and(|state| state.remove_node(id))
    }

    fn set_threshold(&mut self, target: OracleTarget, new_thres: u16) -> bool {
        self.states
            .get_mut(&target)
            .is_some_and(|state| state.set_threshold(new_thres))
    }

    pub fn finalize_epoch(&mut self, target: OracleTarget, target_info: OracleEpochInfo) -> bool {
        let state = self.source_state_mut(target);
        let next_config_hash: Hash = <[u8; 32]>::from(target_info.config_hash).into();
        if target_info.epoch != state.current.epoch.wrapping_add(1) {
            return false;
        }
        let Some((next_config, _)) = state.materialize_prefix(target_info.change_count) else {
            return false;
        };
        if next_config.to_hash(state.cipher) != next_config_hash {
            return false;
        }
        if target_info.change_count > state.staging_ops.len() as u32 {
            return false;
        }
        let trim_len = target_info.change_count as usize;
        let mut next_staging = next_config.clone();
        next_staging.epoch = next_config.epoch.wrapping_add(1);
        for op in state.staging_ops.iter().skip(trim_len) {
            if !next_staging.apply_op(op) {
                return false;
            }
        }
        state.current = next_config;
        state.current_hash = next_config_hash;
        state.staging = next_staging;
        state.staging_ops.drain(..trim_len);
        true
    }

    pub fn propose_advance_epoch(
        &self, target: OracleTarget,
    ) -> Option<(u32, &OracleConfig, OracleConfigDeltaWire, Hash, u32)> {
        let state = self.source_state(target)?;
        if !state.staging.is_valid() {
            return None;
        }
        let change_count = u32::try_from(state.staging_ops.len()).ok()?;
        let (next_config, delta) = state.materialize_prefix(change_count)?;
        let config_hash = next_config.to_hash(state.cipher);
        let config = if state.current.epoch == 0 {
            if change_count == 0 {
                return None;
            }
            &state.staging
        } else {
            &state.current
        };
        Some((state.staging.epoch, config, delta, config_hash, change_count))
    }

    pub fn validate_advance_epoch(
        &self, target: OracleTarget, topic: &str, epoch: u32, config_hash: &Hash, config_delta: &OracleConfigDeltaWire,
        change_count: u32,
    ) -> bool {
        if self.topic != topic {
            return false;
        }
        let Some(state) = self.source_state(target) else {
            return false;
        };
        if !state.staging.is_valid() || epoch != state.staging.epoch {
            return false;
        }
        state
            .materialize_prefix(change_count)
            .is_some_and(|(next_config, expected_delta)| {
                let expected_hash = next_config.to_hash(state.cipher);
                &expected_delta == config_delta && &expected_hash == config_hash
            })
    }

    pub fn validate_finalize_epoch(&self, target: OracleTarget, target_info: &OracleEpochInfo) -> bool {
        lyquor_api::fetch_oracle_info(self.topic.to_string(), target, false)
            .ok()
            .flatten()
            .is_some_and(|observed| {
                let target_hash: Hash = <[u8; 32]>::from(target_info.config_hash).into();
                let observed_hash = Hash::from(<[u8; 32]>::from(observed.config_hash));
                observed.epoch == target_info.epoch &&
                    observed_hash == target_hash &&
                    observed.change_count == target_info.change_count
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
    pub fn add_node<T>(&self, _ctx: &mut T, target: OracleTarget, id: NodeID) -> bool {
        crate::runtime::internal::builtin_network_state()
            .oracle_src_mut(self.topic())
            .add_node(target, id)
    }

    /// Remove a node from the committee. If the node does not exist, returns false.
    pub fn remove_node<T>(&self, _ctx: &mut T, target: OracleTarget, id: NodeID) -> bool {
        crate::runtime::internal::builtin_network_state()
            .oracle_src_mut(self.topic())
            .remove_node(target, id)
    }

    /// Get the currently active oracle config.
    pub fn config_current<T>(&self, _ctx: &T, target: OracleTarget) -> &OracleConfig {
        match crate::runtime::internal::builtin_network_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.source_state(target))
        {
            Some(state) => &state.current,
            None => OracleConfig::empty(),
        }
    }

    /// Get the staged oracle config after applying all queued source-side ops.
    pub fn config_staging<T>(&self, _ctx: &T, target: OracleTarget) -> &OracleConfig {
        match crate::runtime::internal::builtin_network_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.source_state(target))
        {
            Some(state) => &state.staging,
            None => OracleConfig::empty(),
        }
    }

    pub fn get_epoch<T>(&self, _ctx: &T, target: OracleTarget) -> u32 {
        crate::runtime::internal::builtin_network_state()
            .oracle_src(self.topic())
            .and_then(|oracle| oracle.source_state(target))
            .map_or(0, SourceState::get_epoch)
    }

    /// Update the threshold of the oracle.
    pub fn set_threshold<T>(&self, _ctx: &mut T, target: OracleTarget, new_thres: u16) -> bool {
        crate::runtime::internal::builtin_network_state()
            .oracle_src_mut(self.topic())
            .set_threshold(target, new_thres)
    }
}
