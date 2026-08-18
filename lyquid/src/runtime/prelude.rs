// Useful external crates (from LDK deps);
pub use alloy_sol_types;
pub use hashbrown;
pub use lyquor_primitives;
pub use lyquor_primitives::blake3;

pub use lyquor_primitives::{
    Address, Bytes, CallParams, ChainPos, Hash, LyquidID, LyquidNumber, NodeID, RequiredLyquid, TriggerMode, U64, U128,
    U256, address, decode_by_fields, decode_object, encode_by_fields, encode_object, uint,
};

pub use super::lyquor_api;
pub use super::oracle::{CertifiedCallParams, OracleServiceTarget, OracleTarget};
pub use super::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use crate::{LyquidError, LyquidResult};

/// Types returned by [`oneshot()`].
pub mod oneshot {
    pub use crate::runtime::sync::oneshot::{Receiver, RecvError, Sender};
}

/// Creates a guest-side channel that transfers exactly one value between concurrent instance calls.
///
/// Sending never waits. Receiving blocks through the Lyquor host wait/notify primitives until a value
/// arrives or the sender is dropped. The channel is backed by shared instance LyteMemory and is intended
/// for coordination between Lyquid instance functions.
///
/// Like the guest [`Mutex`] and [`RwLock`], this primitive is only supported for short-lived coordination:
/// a waiting receiver keeps its instance call in flight, and a host timeout or cancellation does not
/// guarantee guest-side cleanup. Do not use it for durable external-input waits or recovery across node
/// restarts.
pub fn oneshot<T>() -> (oneshot::Sender<T>, oneshot::Receiver<T>) {
    crate::runtime::sync::oneshot::channel()
}

/// Deterministically seeded hash map used by Lyquid runtime data structures.
pub type HashMap<K, V> = hashbrown::HashMap<K, V, ahash::RandomState>;
/// Deterministically seeded hash set used by Lyquid runtime data structures.
pub type HashSet<K> = hashbrown::HashSet<K, ahash::RandomState>;

/// Creates a deterministically seeded hash map.
pub fn new_hashmap<K, V>() -> HashMap<K, V> {
    HashMap::with_hasher(ahash::RandomState::with_seed(0))
}
/// Creates a deterministically seeded hash set.
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
