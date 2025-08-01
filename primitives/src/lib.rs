#![doc(html_no_source)] // remove it upon open-source

pub extern crate serde;

use std::fmt;

pub use alloy_primitives::hex;
pub use alloy_primitives::{self, Address, B256, U32, U64, U128, U256, address, uint};
pub use anyhow;
pub use blake3;
pub use bytes::{self, Bytes};
pub use cb58;
use futures::channel::oneshot;
pub use parking_lot;
pub use serde::{Deserialize, Serialize};

mod id;
pub use id::{LyquidID, LyquidNumber, NodeID, RequiredLyquid};
pub use typed_builder::TypedBuilder;

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

/// Used by the callee to end the call with a result.
pub struct InterCall(Option<oneshot::Sender<Vec<u8>>>);

impl Default for InterCall {
    fn default() -> Self {
        Self(None)
    }
}

impl Clone for InterCall {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl InterCall {
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

pub const GROUP_DEFAULT: &str = "main";
pub const GROUP_NODE: &str = "node";
pub const GROUP_UPC_CALLEE: &str = "upc_callee";
pub const GROUP_UPC_REQ: &str = "upc_request";
pub const GROUP_UPC_RESP: &str = "upc_response";

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
    #[builder(default = EventABI::Lyquor)]
    pub abi: EventABI,
}

impl<I: Eq> Eq for CallParams<I> {}

impl<I: fmt::Debug> fmt::Debug for CallParams<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "CallParams(caller={}, origin={}, group={}, method={}, input={:?}, abi={:?})",
            self.caller, self.origin, self.group, self.method, &self.input, self.abi
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SeqEvent {
    pub params: CallParams<Bytes>,
    #[serde(skip)]
    pub inter_call: InterCall,
}

impl fmt::Debug for SeqEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "SeqEvent({:?})", self.params)
    }
}

impl PartialEq for SeqEvent {
    fn eq(&self, other: &Self) -> bool {
        self.params.eq(&other.params)
    }
}

impl Eq for SeqEvent {}

impl SeqEvent {
    pub fn new(params: CallParams<Bytes>) -> Self {
        Self {
            params,
            inter_call: InterCall::default(),
        }
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
