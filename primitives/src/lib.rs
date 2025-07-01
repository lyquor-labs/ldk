#![doc(html_no_source)] // remove it upon open-source

pub extern crate serde;

use std::collections::HashMap;
use std::fmt;
use std::hash;
use std::sync::Arc;

pub use alloy_primitives::hex;
pub use alloy_primitives::{self, Address, B256, U32, U64, U128, U256, address, uint};
pub use anyhow;
pub use blake3;
pub use bytes::{self, Bytes};
pub use cb58;
use futures::channel::oneshot;
pub use parking_lot;
use parking_lot::Mutex;
pub use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "api")] pub mod api;
mod id;
pub use id::{LyquidID, LyquidNumber, NodeID};

pub type Hash = blake3::Hash;

/// Position of a slot in the sequencer's backend.
///
/// Typically, a sequencing backend may be a chain that carries Lyquid slots in some of its blocks.
/// This means the [SlotNumber]s do not necessarily correspond to continuous [ChainPos] in the sequencing backend.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChainPos(u128);

impl ChainPos {
    pub const ZERO: Self = Self(0);
    pub fn new(block_position: u64, block_index: u32) -> Self {
        Self((block_position as u128) << 32 | (block_index as u128))
    }

    #[inline(always)]
    pub fn block(&self) -> u64 {
        (self.0 >> 32) as u64
    }

    #[inline(always)]
    pub fn next_block(&self) -> Self {
        Self(((self.0 >> 32) + 1) << 32)
    }
}

impl fmt::Display for ChainPos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "(block={}, log={})", self.0 >> 32, self.0 as u32)
    }
}

impl fmt::Debug for ChainPos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum LyteCallABI {
    Lyquor,
    Eth,
}

/// Lyquid's call signature.
#[derive(Serialize, Deserialize, Clone)]
pub struct LyteCall {
    pub caller: Address,
    pub origin: Address,
    pub method: String,
    pub input: Bytes,
    pub abi: LyteCallABI,

    #[serde(skip)]
    pub inter_call: InterLyteCall,
}

impl fmt::Debug for LyteCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "LyteCall(caller={}, origin={}, method={}, input={}, abi={:?})",
            self.caller,
            self.origin,
            self.method,
            hex::encode(&self.input),
            self.abi
        )
    }
}

impl PartialEq for LyteCall {
    fn eq(&self, other: &Self) -> bool {
        // Compare everything except `call_return`, which can't be trivially compared
        self.caller == other.caller &&
            self.origin == other.origin &&
            self.method == other.method &&
            self.input == other.input &&
            self.abi == other.abi
    }
}
impl Eq for LyteCall {}

/// Used by the callee to end the call with a result.
pub struct InterLyteCall(Option<oneshot::Sender<Vec<u8>>>);

impl Default for InterLyteCall {
    fn default() -> Self {
        Self(None)
    }
}

impl Clone for InterLyteCall {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl InterLyteCall {
    pub fn new() -> (Self, oneshot::Receiver<Vec<u8>>) {
        let (tx, rx) = oneshot::channel();
        let me = Self(Some(tx));
        (me, rx)
    }

    pub fn set_result(&mut self, data: Vec<u8>) {
        if let Some(tx) = self.0.take() {
            tx.send(data).ok();
        }
    }
}

/// All types of Lyquid's events.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum LyteEvent {
    Call(String, LyteCall),
}

impl fmt::Debug for LyteEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        use LyteEvent::*;
        match self {
            Call(group, call) => {
                write!(f, "Call(group={}, call={:?})", group, call)
            }
        }
    }
}

impl LyteEvent {
    // FIXME: fill in the caller
    pub fn new_node_join(node: NodeID) -> Self {
        Self::Call(
            "node".into(),
            LyteCall {
                caller: Address::ZERO,
                origin: Address::ZERO,
                method: "join".into(),
                input: encode_by_fields_!("crate::serde", node: NodeID).into(),
                abi: LyteCallABI::Lyquor,
                inter_call: Default::default(),
            },
        )
    }

    // FIXME: fill in the caller
    pub fn new_node_leave(node: NodeID) -> Self {
        Self::Call(
            "node".into(),
            LyteCall {
                caller: Address::ZERO,
                origin: Address::ZERO,
                method: "leave".to_string(),
                input: encode_by_fields_!("crate::serde", node: NodeID).into(),
                abi: LyteCallABI::Lyquor,
                inter_call: Default::default(),
            },
        )
    }
}

pub type LyteLogTopic = B256;

#[derive(Serialize, Deserialize, Clone)]
pub struct LyteLog {
    pub topics: [Option<Box<LyteLogTopic>>; 4],
    pub data: Bytes,
}

impl LyteLog {
    pub fn new_from_tagged_value<V: Serialize>(tag: &str, value: &V) -> Self {
        let topic0 = Box::new(Self::tagged_value_topic(tag));
        Self {
            topics: [Some(topic0), None, None, None],
            data: encode_object(value).into(),
        }
    }

    pub fn tagged_value_topic(tag: &str) -> LyteLogTopic {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tag.as_bytes());
        let topic: [u8; 32] = hasher.finalize().into();
        topic.into()
    }
}

impl fmt::Debug for LyteLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "LyteLog(topics={}, data=<{} bytes>)",
            self.topics
                .iter()
                .map(|t| match t {
                    Some(t) => t.to_string(),
                    None => "_".into(),
                })
                .collect::<Vec<_>>()
                .join(", "),
            self.data.len()
        )
    }
}

pub fn decode_object<T: for<'a> Deserialize<'a>>(raw: &[u8]) -> Option<T> {
    alkahest::deserialize::<alkahest::Bincode, T>(raw).ok()
}

pub fn encode_object<T: Serialize + ?Sized>(obj: &T) -> Vec<u8> {
    let mut raw = Vec::new();
    alkahest::serialize_to_vec::<alkahest::Bincode, &T>(obj, &mut raw);
    raw
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum StateCategory {
    Network,
    Instance,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleSink {
    StdOut,
    StdErr,
}

enum LazyByteChunk {
    Parts(Arc<Mutex<LazyByteChunk>>, Arc<Mutex<LazyByteChunk>>),
    Leaf(Bytes),
}

/// A byte array that be quickly prefixed/suffixed/cloned with little cost. The [Self::consolidated]
/// method returns its full content which triggers the final concatenation once. This is useful for
/// zero-copy key prefixing.
#[derive(Clone)]
pub struct LazyBytes(Arc<Mutex<LazyByteChunk>>);

struct LazyByteChunkIter {
    stack: Vec<Arc<Mutex<LazyByteChunk>>>,
}

impl LazyByteChunkIter {
    fn new(root: Arc<Mutex<LazyByteChunk>>) -> Self {
        Self { stack: vec![root] }
    }
}

impl Iterator for LazyByteChunkIter {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(chunk) = self.stack.pop() {
            match &*chunk.lock() {
                LazyByteChunk::Parts(left, right) => {
                    self.stack.push(right.clone());
                    self.stack.push(left.clone());
                }
                LazyByteChunk::Leaf(bytes) => {
                    return Some(bytes.clone());
                }
            }
        }
        None
    }
}

impl LazyBytes {
    pub fn consolidated(&self) -> Bytes {
        if let LazyByteChunk::Leaf(bytes) = &*self.0.lock() {
            return bytes.clone();
        }

        // First pass: calculate total size
        let total_size: usize = LazyByteChunkIter::new(self.0.clone()).map(|bytes| bytes.len()).sum();

        // Pre-allocate the final vector
        let mut consolidated = Vec::with_capacity(total_size);

        // Second pass: fill the pre-allocated vector
        for bytes in LazyByteChunkIter::new(self.0.clone()) {
            consolidated.extend_from_slice(&bytes);
        }

        let consolidated: Bytes = consolidated.into();
        *self.0.lock() = LazyByteChunk::Leaf(consolidated.clone());
        consolidated
    }

    pub fn append(&self, suffix: &Self) -> Self {
        Self(Arc::new(Mutex::new(LazyByteChunk::Parts(
            self.0.clone(),
            suffix.0.clone(),
        ))))
    }

    pub fn prepend(&self, prefix: &Self) -> Self {
        Self(Arc::new(Mutex::new(LazyByteChunk::Parts(
            prefix.0.clone(),
            self.0.clone(),
        ))))
    }
}

impl hash::Hash for LazyBytes {
    fn hash<H>(&self, hasher: &mut H)
    where
        H: std::hash::Hasher,
    {
        hasher.write(&self.consolidated());
    }
}

impl PartialEq for LazyBytes {
    fn eq(&self, other: &Self) -> bool {
        self.consolidated().eq(&other.consolidated())
    }
}

impl Eq for LazyBytes {}

impl From<Bytes> for LazyBytes {
    fn from(src: Bytes) -> LazyBytes {
        LazyBytes(Arc::new(Mutex::new(LazyByteChunk::Leaf(src))))
    }
}

impl From<Vec<u8>> for LazyBytes {
    fn from(src: Vec<u8>) -> LazyBytes {
        Bytes::from(src).into()
    }
}

impl<const N: usize> From<[u8; N]> for LazyBytes {
    fn from(src: [u8; N]) -> LazyBytes {
        Vec::from(src).into()
    }
}

impl<const N: usize> From<&[u8; N]> for LazyBytes {
    fn from(src: &[u8; N]) -> LazyBytes {
        Vec::from(src).into()
    }
}

impl From<&[u8]> for LazyBytes {
    fn from(src: &[u8]) -> LazyBytes {
        Vec::from(src).into()
    }
}

impl fmt::Debug for LazyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        self.consolidated().fmt(f)
    }
}

#[test]
fn test_lazy_bytes() {
    let a = LazyBytes::from(b"hello");
    let b = LazyBytes::from(b"world");
    let c = a.append(&b);
    let d = c.append(&b"another".into());
    let e = c.prepend(&b"prefix".into());
    assert_eq!("helloworld", std::str::from_utf8(&c.consolidated()).unwrap());
    assert_eq!(LazyBytes::from(b"helloworldanother"), d);
    assert_eq!(LazyBytes::from(b"prefixhelloworld"), e.clone());
}

#[test]
fn test_lazy_bytes_partial_consolidation() {
    // Create base LazyBytes
    let a = LazyBytes::from(b"hello");
    let b = LazyBytes::from(b"world");
    let c = LazyBytes::from(b"rust");
    let d = LazyBytes::from(b"lang");

    // Create a complex tree structure
    let ab = a.append(&b); // "helloworld"
    let cd = c.append(&d); // "rustlang"
    let ab_cd = ab.append(&cd); // "helloworldrustlang"

    // Consolidate and verify parts
    assert_eq!("helloworld", std::str::from_utf8(&ab.consolidated()).unwrap());
    assert_eq!("rustlang", std::str::from_utf8(&cd.consolidated()).unwrap());

    // Further complex operations
    let e = LazyBytes::from(b"test");
    let ab_cd_e = ab_cd.append(&e); // "helloworldrustlangtest"
    let e_ab_cd = e.prepend(&ab_cd); // "helloworldrustlangtest"

    // Consolidate and verify further parts
    assert_eq!(
        "helloworldrustlang",
        std::str::from_utf8(&ab_cd.consolidated()).unwrap()
    );
    assert_eq!(
        "helloworldrustlangtest",
        std::str::from_utf8(&ab_cd_e.consolidated()).unwrap()
    );
    assert_eq!(
        "helloworldrustlangtest",
        std::str::from_utf8(&e_ab_cd.consolidated()).unwrap()
    );
}

pub fn encode_method_name<M: fmt::Display>(cat_prefix: &str, group: &str, method: M) -> String {
    let mut output = cat_prefix.to_string();
    output.push('_');
    cb58::bs58::encode(blake3::hash(group.as_bytes()).as_bytes())
        .onto(&mut output)
        .unwrap();
    output.push('_');
    output.push_str(&method.to_string());
    output
}

#[doc(hidden)]
#[macro_export]
macro_rules! object_by_fields_ {
    ($serde_crate: tt, $($var:ident: $type:ty = $val:expr),*) => {{
        #[allow(non_camel_case_types)]
        #[derive($crate::Serialize)]
        #[serde(crate = $serde_crate)]
        struct parameters { $($var:$type),* }
        parameters { $($var: $val),* }
    }};
}

#[macro_export]
macro_rules! object_by_fields {
    ($($token: tt)*) => {{
        $crate::object_by_fields_!("lyquor_primitives::serde", $($token)*)
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! encode_by_fields_ {
    ($serde_crate: tt, $($var:ident: $type:ty = $val:expr),*) => {{
        $crate::encode_object(&$crate::object_by_fields_!($serde_crate, $($var: $type = $val),*))
    }};
    ($serde_crate: tt, $($var:ident: $type:ty),*) => {{
        $crate::encode_object(&$crate::object_by_fields_!($serde_crate, $($var: $type = $var),*))
    }};
}

#[macro_export]
macro_rules! encode_by_fields {
    ($($token: tt)*) => {{
        $crate::encode_by_fields_!("lyquor_primitives::serde", $($token)*)
    }};
}

#[macro_export]
macro_rules! decode_by_fields {
    ($encoded:expr, $($var:ident: $type:ty),*) => {{
        #[allow(non_camel_case_types)]
        #[derive($crate::Deserialize)]
        #[serde(crate = "lyquor_primitives::serde")]
        struct parameters { $($var:$type),* }
        $crate::decode_object::<parameters>($encoded)
    }};
}

pub type Key = LazyBytes;
pub type Value = Bytes;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct KVStoreError(#[from] anyhow::Error);

/// Abstraction for a generic key-value store.
pub trait KVStore: Send + Sync {
    /// Retrieve the value mapped from the given key.
    fn get(&self, key: Key) -> Result<Option<Value>, KVStoreError>;
    /// Write a batch of updates with atomicity to the store. Any changes written should be
    /// immediately visible in [Self::get].
    fn atomic_write<'a>(
        &'a self, changes: Box<dyn Iterator<Item = (Key, Option<Value>)> + 'a>,
    ) -> Result<(), KVStoreError>;
}

impl<T: KVStore + ?Sized> KVStore for Arc<T> {
    #[inline(always)]
    fn get(&self, key: Key) -> Result<Option<Value>, KVStoreError> {
        self.as_ref().get(key)
    }
    #[inline(always)]
    fn atomic_write<'a>(
        &self, changes: Box<dyn Iterator<Item = (Key, Option<Value>)> + 'a>,
    ) -> Result<(), KVStoreError> {
        self.as_ref().atomic_write(changes)
    }
}

/// Wrapper that logically behaves as a key-value store whose keys are always prefixed by `prefix`.
pub struct PrefixedKVStore<S: KVStore> {
    inner: S,
    prefix: Key,
}

impl<S: KVStore> PrefixedKVStore<S> {
    pub fn new(inner: S, prefix: Key) -> Self {
        // Let's first consolidated here because it'll be used every time upon `get()`
        prefix.consolidated();
        Self { inner, prefix }
    }
}

impl<S: KVStore> KVStore for PrefixedKVStore<S> {
    #[inline]
    fn get(&self, key: Key) -> Result<Option<Value>, KVStoreError> {
        self.inner.get(self.prefix.append(&key))
    }

    #[inline]
    fn atomic_write<'a>(
        &'a self, changes: Box<dyn Iterator<Item = (Key, Option<Value>)> + 'a>,
    ) -> Result<(), KVStoreError> {
        self.inner
            .atomic_write(Box::new(changes.map(|(k, v)| (self.prefix.append(&k), v))))
    }
}

/// This store will buffer all the atomic writes made by `atomic_write`, until the invocation of
/// `commit`. This creates a tranasprent layer to defer/aggregate the writes into a coarser atomic commit.
pub struct ShadowKVStore<S: KVStore> {
    inner: S,
    writes: parking_lot::RwLock<HashMap<Key, Option<Value>>>,
}

impl<S: KVStore> ShadowKVStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            writes: parking_lot::RwLock::new(HashMap::new()),
        }
    }
}

impl<S: KVStore> KVStore for ShadowKVStore<S> {
    #[inline]
    fn get(&self, key: Key) -> Result<Option<Value>, KVStoreError> {
        self.writes
            .read()
            .get(&key)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| self.inner.get(key))
    }

    #[inline]
    fn atomic_write<'a>(
        &'a self, changes: Box<dyn Iterator<Item = (Key, Option<Value>)> + 'a>,
    ) -> Result<(), KVStoreError> {
        let mut writes = self.writes.write();
        for (k, v) in changes {
            writes.insert(k, v);
        }
        Ok(())
    }
}

impl<S: KVStore> ShadowKVStore<S> {
    pub fn changes(&self) -> parking_lot::RwLockWriteGuard<HashMap<Key, Option<Value>>> {
        self.writes.write()
    }

    pub fn commit(&self) -> Result<(), KVStoreError> {
        let mut changes = self.changes(); // DO NOT remove this line, see below
        self.inner
            .atomic_write(Box::new(std::mem::take(&mut *changes).into_iter()))
        // changes unlocked after the atomic_write is done, so the original changes are visible again
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! subkey_builder_ {
    ($subkey:ident, {}, {$($methods:tt)*}, {$($defs:tt)*}, {$($inits:tt)*}) => {
        struct $subkey {
            key: Key,
            $($defs)*
        }

        impl $subkey {
            pub fn new(key: Key) -> Self {
                Self {
                    key,
                    $($inits)*
                }
            }

            pub fn prefix(&self) -> &Key {
                &self.key
            }

            $($methods)*
        }

        impl From<Key> for $subkey {
            fn from(key: Key) -> Self {
                Self::new(key)
            }
        }

        impl Clone for $subkey {
            fn clone(&self) -> Self {
                Self::new(self.key.clone())
            }
        }
    };
    ($subkey:ident, {($suffix:expr)-$name:ident() => $key:ty $(, $($rest:tt)*)?}, {$($methods:tt)*}, {$($defs:tt)*}, {$($inits:tt)*}) => {
        $crate::subkey_builder_!(
            $subkey,
            {$($($rest)*)?},
            {
                pub fn $name(&self) -> $key {
                    self.$name
                        .get_or_init(|| self.key.append(&$suffix.into()).into()).clone()
                }
                $($methods)*
            },
            {
                $name: std::sync::OnceLock<$key>,
                $($defs)*
            },
            {
                $name: std::sync::OnceLock::new(),
                $($inits)*
            });
    };
    ($subkey:ident, {($suffix:expr)-$name:ident($suffix2:ty) => $key:ty $(, $($rest:tt)*)?}, {$($methods:tt)*}, {$($defs:tt)*}, {$($inits:tt)*}) => {
        $crate::subkey_builder_!(
            $subkey,
            {$($($rest)*)?},
            {
                pub fn $name(&self, suffix: $suffix2) -> $key {
                    self.$name
                        .get_or_init(|| {
                            let subkey = self.key.append(&$suffix.into());
                            subkey.consolidated();
                            subkey
                        })
                        .append(&$crate::encode_object(suffix).into()).into()
                }
                $($methods)*
            },
            {
                $name: std::sync::OnceLock<Key>,
                $($defs)*
            },
            {
                $name: std::sync::OnceLock::new(),
                $($inits)*
            }
        );
    };
}

#[macro_export]
macro_rules! subkey_builder {
    ($subkey: ident($($rest:tt)*)) => {
        $crate::subkey_builder_!($subkey, {$($rest)*}, {}, {}, {});
    };
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Range<T> {
    pub start: Option<T>,
    pub end: Option<T>,
}
