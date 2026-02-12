// Useful external crates (from LDK deps);
pub use alloy_dyn_abi;
pub use hashbrown;
pub use lyquor_primitives;
pub use lyquor_primitives::blake3;

pub use lyquor_primitives::{
    Address, Bytes, CallParams, ChainPos, Hash, LyquidID, LyquidNumber, NodeID, RequiredLyquid, TriggerMode, U64, U128,
    U256, address, decode_by_fields, decode_object, encode_by_fields, encode_object, uint,
};

pub use super::lyquor_api;
pub use super::oracle::{CertifiedCallParams, OracleTarget};
pub use super::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use crate::{LyquidError, LyquidResult};

pub type HashMap<K, V> = hashbrown::HashMap<K, V, ahash::RandomState>;
pub type HashSet<K> = hashbrown::HashSet<K, ahash::RandomState>;

pub fn new_hashmap<K, V>() -> HashMap<K, V> {
    HashMap::with_hasher(ahash::RandomState::with_seed(0))
}
pub fn new_hashset<K>() -> HashSet<K> {
    HashSet::with_hasher(ahash::RandomState::with_seed(0))
}

// Macros
pub use crate::{
    call, decode_eth_call_params, encode_eth_call_params, eprint, eprintln, log, print, println, state,
    submit_certified_call, trigger, upc,
};

pub use crate::http;
pub use crate::method::{self};
