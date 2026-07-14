//! Stable primitive types shared below Lyquor subsystem boundaries.
//!
//! This crate is intentionally low in the dependency graph. It defines identifiers, address and
//! byte aliases, sequence positions, Lyquid numbers, call parameters, state categories, log and
//! console records, and oracle wire types. API, VM, networking, state, and tooling crates depend on
//! these primitives when they need the same serialized shape without importing each other's logic.

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
/// Oracle configuration, certificates, and wire-message primitives.
pub mod oracle;
pub use id::{LyquidID, LyquidNumber, NodeID, RequiredLyquid, SequenceBackendID, sequence_backend_id};

/// Serde helpers for fields shaped as `Option<Arc<T>>`.
pub mod arc_option_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize `Option<Arc<T>>` as if it were `Option<T>`.
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

    /// Deserialize `Option<T>` and wrap the present value in `Arc`.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Arc<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let opt = Option::<T>::deserialize(deserializer)?;
        Ok(opt.map(Arc::new))
    }
}

/// Canonical hash type used for Lyquor primitive wrappers.
pub type Hash = blake3::Hash;

// Network definitions moved to lyquor-api::profile.

/// Position of a slot in the sequencer's backend.
///
/// Typically, a sequencing backend may be a chain that carries Lyquid slots in some of its blocks.
/// This means sequencer slot numbers do not necessarily correspond to continuous [`ChainPos`]
/// values in the sequencing backend.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainPos(u128);

impl ChainPos {
    /// Zero block position and zero block index.
    pub const ZERO: Self = Self(0);
    /// Construct a packed chain position from a block position and in-block index.
    pub fn new(block_position: u64, block_index: u32) -> Self {
        Self((block_position as u128) << 32 | (block_index as u128))
    }

    /// Return the block position component.
    #[inline(always)]
    pub fn block(&self) -> u64 {
        (self.0 >> 32) as u64
    }

    /// Return the in-block index component.
    #[inline(always)]
    pub fn block_index(&self) -> u32 {
        self.0 as u32
    }

    /// Return the first position in the next block.
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

/// Input ABI used to decode a Lyquid method call.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum InputABI {
    /// Native Lyquor field encoding.
    Lyquor,
    /// Ethereum ABI encoding.
    Eth,
}

/// Scheduling mode for an instance trigger.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TriggerMode {
    /// Trigger repeatedly at the specified interval in milliseconds.
    Recurrent(u64),
    /// Trigger once, delayed by the specified milliseconds (0 for immediate).
    Once(u64),
    /// Trigger once after the current slot commits successfully.
    Commit,
    /// Stop the trigger (remove it from the registry).
    Stop,
}

/// Serializable wrapper around a 32-byte BLAKE3 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct HashBytes(Hash);

impl HashBytes {
    /// Wrap a BLAKE3 hash.
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Consume the wrapper and return the inner BLAKE3 hash.
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
        Ok(Self(blake3::Hash::from(array)))
    }
}

/// Encoded call metadata delivered to Lyquid methods.
#[derive(Serialize, Deserialize, PartialEq, Clone, TypedBuilder)]
pub struct CallParams {
    /// The ultimate origin of the call (the transaction signer, for example if the call comes from
    /// the chain. The default is zero address when unused.
    #[builder(default = Address::ZERO)]
    pub origin: Address,
    /// The direct caller.
    pub caller: Address,
    /// Method group namespace; defaults to [`GROUP_DEFAULT`].
    #[builder(default = GROUP_DEFAULT.into())]
    pub group: String,
    /// Method name within the selected group.
    pub method: String,
    /// Encoded input payload.
    pub input: Bytes,
    /// ABI used to decode `input`.
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

/// Default method group used when no explicit group is selected.
pub const GROUP_DEFAULT: &str = "main";
/// Built-in node group used for node-membership calls.
pub const GROUP_NODE: &str = "node";
/// Built-in UPC prepare group.
pub const GROUP_UPC_PREPARE: &str = "upc::prepare";
/// Built-in UPC request group.
pub const GROUP_UPC_REQ: &str = "upc::request";
/// Built-in UPC response group.
pub const GROUP_UPC_RESP: &str = "upc::response";

/// Log topic hash type.
pub type LyteLogTopic = B256;

/// Log record emitted by a Lyquid network function.
#[derive(Serialize, Deserialize, Clone)]
pub struct LyteLog {
    /// Up to four optional indexed topics.
    pub topics: [Option<Box<LyteLogTopic>>; 4],
    /// Encoded event payload.
    pub data: Bytes,
}

impl LyteLog {
    /// Build a log from a tag and serializable value.
    pub fn new_from_tagged_value<V: Serialize>(tag: &str, value: &V) -> Self {
        let topic0 = Box::new(Self::tagged_value_topic(tag));
        Self {
            topics: [Some(topic0), None, None, None],
            data: encode_object(value).into(),
        }
    }

    /// Compute the first topic used for a tagged value log.
    pub fn tagged_value_topic(tag: &str) -> LyteLogTopic {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tag.as_bytes());
        let topic: [u8; 32] = hasher.finalize().into();
        topic.into()
    }
}

/// Registry event emitted when a Lyquid deployment is registered.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterEvent {
    /// Registered Lyquid ID.
    pub id: LyquidID,
    /// Direct Lyquid dependencies declared at registration time.
    pub deps: Vec<LyquidID>,
}

/// Availability lifecycle of one Lyquid deployment in the bartender registry.
///
/// `Pending` deployments are registered but not yet hostable anywhere; a
/// threshold certificate over "we hold this image digest" flips them to
/// `Live`, which is when nodes start hosting. `Void` marks a deployment whose
/// image was certified unavailable; it can never become hostable.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeployStatus {
    /// Registered; awaiting an availability verdict. Not hostable.
    Pending,
    /// Availability certified (or the gate is inactive). Hostable.
    Live,
    /// Certified unavailable at deployment. Never hostable.
    Void,
}

/// Registry event emitted when a deployment is registered with `Pending`
/// availability, prompting nodes to pull the image and certify it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AvailabilityPendingEvent {
    /// Registered Lyquid ID.
    pub id: LyquidID,
    /// Index of this deployment in the Lyquid's deployment history.
    pub nth: u32,
    /// Content digest of the deployment's image pack.
    pub image_digest: B256,
    /// Advisory repository locator supplied at registration.
    pub repo_hint: Option<String>,
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

/// Decode a postcard object, returning `None` on malformed bytes.
pub fn decode_object<T: for<'a> Deserialize<'a>>(raw: &[u8]) -> Option<T> {
    postcard::from_bytes(raw).ok()
}

/// Encode a serializable object with postcard.
pub fn encode_object<T: Serialize + ?Sized>(obj: &T) -> Vec<u8> {
    postcard::to_stdvec(obj).expect("postcard serialization failed")
}

/// Encode a serializable object with a raw prefix prepended before the postcard payload.
pub fn encode_object_with_prefix<T: Serialize + ?Sized>(prefix: &[u8], obj: &T) -> Vec<u8> {
    let mut vec = Vec::with_capacity(prefix.len() + core::mem::size_of_val(obj));
    vec.extend_from_slice(prefix);
    postcard::to_io(obj, &mut vec).expect("postcard serialization failed");
    vec
}

/// State category that determines sequencing and persistence semantics.
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
pub enum StateCategory {
    /// Globally sequenced state.
    Network,
    /// Node-local state.
    Instance,
}

impl StateCategory {
    /// Return the numeric runtime tag used in guest memory headers.
    pub fn as_runtime(&self) -> u8 {
        match self {
            Self::Instance => 0x1,
            Self::Network => 0x2,
        }
    }
}

/// Console stream selected by a guest log message.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[serde(rename_all = "camelCase")]
pub enum ConsoleSink {
    /// Standard output stream.
    StdOut,
    /// Standard error stream.
    StdErr,
}

/// Encode a `(category prefix, group, method)` tuple into the exported WASM function name.
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

/// Optional range used by API filters.
#[derive(Serialize, Deserialize, Debug)]
pub struct Range<T> {
    /// Optional start bound.
    pub start: Option<T>,
    /// Optional end bound.
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
