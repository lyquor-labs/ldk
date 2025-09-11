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
pub enum EventABI {
    Lyquor,
    Eth,
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
pub struct CallParams<I> {
    /// The ultimate origin of the call (the transaction signer, for example if the call comes from
    /// the chain. The default is zero address when unused.
    #[builder(default = Address::ZERO)]
    pub origin: Address,
    /// The direct caller.
    pub caller: Address,
    #[builder(default = GROUP_DEFAULT.into())]
    pub group: String,
    pub method: String,
    pub input: I,
    #[builder(default = None)]
    #[serde(with = "arc_option_serde", default)]
    pub input_cert: Option<Arc<OracleCert>>,
    #[builder(default = EventABI::Lyquor)]
    pub abi: EventABI,
}

impl<I: Eq> Eq for CallParams<I> {}

impl fmt::Debug for CallParams<Bytes> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "CallParams(caller={}, origin={}, group={}, method={}, input={}, input_cert={:?}, abi={:?})",
            self.caller,
            self.origin,
            self.group,
            self.method,
            hex::encode(&self.input),
            self.input_cert,
            self.abi
        )
    }
}

pub type Signature = (); // TODO
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Certificate; // TODO
pub type PubKey = (); // TODO

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum OracleTarget {
    // Lyquor network fn
    Lyquor(LyquidID),
    // Native contract of the sequence backend (such as EVM)
    SequenceVM(Address),
}

/// Contains other fields needed to define a call alongside the standard call parameters.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct OracleHeader {
    /// The node that proposed the call for certification.
    pub proposer: NodeID,
    /// The way the call will end (e.g., to be a network fn call, or to call the sequencing chain's
    /// own VM.)
    pub target: OracleTarget,
    /// The hash of the oracle config.
    pub config_hash: HashBytes,
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub struct OracleSigner {
    pub id: NodeID,
    pub key: PubKey,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleConfig {
    pub committee: Vec<OracleSigner>,
    pub threshold: usize,
}

/// UPC message sent to each signer. The signer will check config hash to see if it's consistent
/// with its oracle state as of the given network state version, and then run `validate`, a
/// signature will be automatically signed using the derived key, and respond to the caller if it
/// `validate()` returns true.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleMessage {
    pub header: OracleHeader,
    /// params.input_cert will be None and unused.
    pub params: CallParams<Bytes>,
}

#[derive(Serialize, Deserialize)]
pub struct OracleResponse {
    pub approval: bool,
    /// Signer signs on hash(<OracleMessage> and <approval bool>)
    pub sig: Signature,
}

impl OracleResponse {
    pub fn sign(msg: OracleMessage, approval: bool) -> Self {
        // TODO
        let _ = msg;
        Self { approval, sig: () }
    }

    pub fn verify(&self, msg_hash: &Hash) -> bool {
        // TODO
        let _ = msg_hash;
        true
    }
}

/// Oracle certificate that could be sequenced.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct OracleCert {
    pub header: OracleHeader,
    // If Some, a new config is agreed upon for this and following certificates, and becomes
    // effective until the next update.
    pub new_config: Option<OracleConfig>,
    // The certificate that shows a threshold approval (could be implemented by a vector of multi
    // sigs).
    pub cert: Certificate,
}

impl Certificate {
    pub fn new(sigs: Vec<(OracleSigner, Signature)>) -> Self {
        // TODO
        let _ = sigs;
        Self
    }

    pub fn verify(&self, input: &CallParams<Bytes>) -> bool {
        // TODO
        let _ = input;
        true
    }
}

impl OracleCert {
    pub fn verify(&self, caller: &Address, input: Bytes) -> bool {
        // TODO
        let _ = (caller, input);
        true
    }
}

pub const GROUP_DEFAULT: &str = "main";
pub const GROUP_NODE: &str = "node";
pub const GROUP_UPC_CALLEE: &str = "upc::callee";
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
