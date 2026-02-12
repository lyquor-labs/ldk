extern crate self as lyquor_primitives;
pub extern crate serde;

use std::fmt;
use std::sync::Arc;

pub use alloy_primitives::hex;
pub use alloy_primitives::{self, Address, B256, U32, U64, U128, U256, address, uint};
pub use blake3;
pub use bytes::{self, Bytes};
pub use cb58;
pub use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

mod id;
pub mod oracle;
pub use id::{LyquidID, LyquidNumber, NodeID, RequiredLyquid};

// Custom serde module for Arc<Option<T>>
pub mod arc_option_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S>(value: &Option<Arc<T>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        match value {
            Some(arc) => Some(arc.as_ref()).serialize(serializer),
            None => Option::<&T>::None.serialize(serializer),
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Arc<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let opt = Option::<T>::deserialize(deserializer)?;
        Ok(opt.map(Arc::new))
    }
}

pub type Hash = blake3::Hash;

// Network definitions moved to lyquor-api::profile.

/// Position of a slot in the sequencer's backend.
///
/// Typically, a sequencing backend may be a chain that carries Lyquid slots in some of its blocks.
/// This means the [SlotNumber]s do not necessarily correspond to continuous [ChainPos] in the sequencing backend.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub fn block_index(&self) -> u32 {
        self.0 as u32
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HumanReadableChainPos {
    block_number: U64,
    block_index: U32,
}

impl Serialize for ChainPos {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            HumanReadableChainPos {
                block_number: U64::from(self.block()),
                block_index: U32::from(self.block_index()),
            }
            .serialize(serializer)
        } else {
            serializer.serialize_u128(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ChainPos {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let HumanReadableChainPos {
                block_number,
                block_index,
            } = HumanReadableChainPos::deserialize(deserializer)?;
            Ok(Self::new(block_number.to::<u64>(), block_index.to::<u32>()))
        } else {
            Ok(Self(u128::deserialize(deserializer)?))
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum InputABI {
    Lyquor,
    Eth,
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TriggerMode {
    /// Trigger repeatedly at the specified interval in milliseconds.
    Recurrent(u64),
    /// Trigger once, delayed by the specified milliseconds (0 for immediate).
    Once(u64),
    /// Trigger once immediately and wait for completion.
    Sync,
    /// Stop the trigger (remove it from the registry).
    Stop,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct HashBytes(Hash);

impl HashBytes {
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    pub fn into_inner(self) -> Hash {
        self.0
    }
}

impl std::ops::Deref for HashBytes {
    type Target = Hash;
    fn deref(&self) -> &Hash {
        &self.0
    }
}

impl From<[u8; 32]> for HashBytes {
    fn from(hash: [u8; 32]) -> Self {
        Self(hash.into())
    }
}

impl From<HashBytes> for [u8; 32] {
    fn from(hash: HashBytes) -> Self {
        hash.0.into()
    }
}

impl From<Hash> for HashBytes {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<HashBytes> for Hash {
    fn from(hash_bytes: HashBytes) -> Self {
        hash_bytes.0
    }
}

impl Serialize for HashBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes: &[u8; 32] = self.0.as_bytes();
        serializer.serialize_bytes(bytes)
    }
}

impl<'de> Deserialize<'de> for HashBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom(format!(
                "Expected 32 bytes for HashBytes, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(HashBytes(blake3::Hash::from(array)))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, TypedBuilder)]
pub struct CallParams {
    /// The ultimate origin of the call (the transaction signer, for example if the call comes from
    /// the chain. The default is zero address when unused.
    #[builder(default = Address::ZERO)]
    pub origin: Address,
    /// The direct caller.
    pub caller: Address,
    #[builder(default = GROUP_DEFAULT.into())]
    pub group: String,
    pub method: String,
    pub input: Bytes,
    #[builder(default = InputABI::Lyquor)]
    pub abi: InputABI,
}

impl Eq for CallParams {}

impl fmt::Debug for CallParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "CallParams(caller={}, origin={}, group={}, method={}, input={}, abi={:?})",
            self.caller,
            self.origin,
            self.group,
            self.method,
            hex::encode(&self.input),
            self.abi
        )
    }
}

pub const GROUP_DEFAULT: &str = "main";
pub const GROUP_NODE: &str = "node";
pub const GROUP_UPC_PREPARE: &str = "upc::prepare";
pub const GROUP_UPC_REQ: &str = "upc::request";
pub const GROUP_UPC_RESP: &str = "upc::response";

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterEvent {
    pub id: LyquidID,
    pub deps: Vec<LyquidID>,
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
    postcard::from_bytes(raw).ok()
}

pub fn encode_object<T: Serialize + ?Sized>(obj: &T) -> Vec<u8> {
    postcard::to_stdvec(obj).expect("postcard serialization failed")
}

pub fn encode_object_with_prefix<T: Serialize + ?Sized>(prefix: &[u8], obj: &T) -> Vec<u8> {
    let mut vec = Vec::with_capacity(prefix.len() + core::mem::size_of_val(obj));
    vec.extend_from_slice(prefix);
    postcard::to_io(obj, &mut vec).expect("postcard serialization failed");
    vec
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
pub enum StateCategory {
    Network,
    Instance,
}

impl StateCategory {
    pub fn as_runtime(&self) -> u8 {
        match self {
            Self::Instance => 0x1,
            Self::Network => 0x2,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleSink {
    StdOut,
    StdErr,
}

pub fn encode_method_name(cat_prefix: &str, group: &str, method: &str) -> String {
    let mut output = cat_prefix.to_string();
    output.push('_');
    cb58::bs58::encode(group.as_bytes()).onto(&mut output).unwrap();
    output.push('_');
    output.push_str(method);
    output
}

#[doc(hidden)]
#[macro_export]
macro_rules! object_by_fields_ {
    ($serde_crate: tt, $($var:ident: $type:ty = $val:expr),*) => {{
        #[allow(non_camel_case_types)]
        #[derive($crate::Serialize, Clone)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Range<T> {
    pub start: Option<T>,
    pub end: Option<T>,
}

#[macro_export]
macro_rules! debug_struct_name {
    ($t:ty) => {
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($t))
            }
        }
    };
}

/// Signature scheme used when requesting signatures from the host.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum Cipher {
    Ed25519,
    Secp256k1,
}
