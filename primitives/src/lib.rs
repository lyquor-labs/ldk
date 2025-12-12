extern crate self as lyquor_primitives;
pub extern crate serde;

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use ed25519_compact::PublicKey;

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

/// High-level network profile for Lyquor deployments.
///
/// This enum is shared across TLS, oracle key derivation and other places that
/// need to distinguish devnet/testnet/mainnet behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Network {
    Devnet,
    Testnet,
    Mainnet,
}

impl Network {
    pub fn as_str(&self) -> &str {
        match self {
            Network::Devnet => "devnet",
            Network::Testnet => "testnet",
            Network::Mainnet => "mainnet",
        }
    }

    pub fn dns_suffix(&self) -> &str {
        match self {
            Network::Devnet => "dev.lyquor.net",
            Network::Testnet => "test.lyquor.net",
            Network::Mainnet => "lyquor.network",
        }
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "devnet" => Ok(Network::Devnet),
            "testnet" => Ok(Network::Testnet),
            "mainnet" => Ok(Network::Mainnet),
            _ => Err(format!("Invalid network: {}", s)),
        }
    }
}

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
pub enum InputABI {
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

/// Opaque oracle signature bytes. Produced and verified by the host using
/// ed25519 (ed25519-compact) over a canonical oracle message digest.
pub type Signature = Bytes;
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Certificate {
    /// Bitmap of signer indices (1-based in on-chain; store as 0-based LVM).
    /// Bit i set means signer at index i in the committee approved.
    pub signer_bitmap: u32,
    /// Concatenated signatures.
    pub signatures: Bytes,
    /// Canonical oracle digest that signers are expected to have signed.
    pub digest: HashBytes,
}
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PubKey(pub PublicKey);

impl From<PublicKey> for PubKey {
    fn from(pk: PublicKey) -> Self {
        Self(pk)
    }
}

impl From<PubKey> for PublicKey {
    fn from(pk: PubKey) -> Self {
        pk.0
    }
}

impl std::ops::Deref for PubKey {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_ref())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != PublicKey::BYTES {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"32 bytes"));
        }
        let pk = PublicKey::from_slice(&bytes).map_err(|_| serde::de::Error::custom("invalid ed25519 public key"))?;
        Ok(PubKey(pk))
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum OracleTarget {
    // Lyquor network fn
    Lyquor(LyquidID),
    // Native contract of the sequence backend (such as EVM)
    SequenceVM(Address),
    // Detect sequence backend
    // TODO: add target chain ID
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
    /// Hybrid replay prevention: epoch controls stale-proof rejection across epochs.
    pub epoch: u32,
    /// Hybrid replay prevention: random nonce for dedup inside an epoch.
    pub nonce: [u8; 32],
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
    pub params: CallParams,
}

#[derive(Serialize, Deserialize)]
pub struct OracleResponse {
    pub approval: bool,
    /// Ed25519 signature over the canonical oracle message digest.
    pub ed25519_sig: Signature,
    /// Optional EVM-side ECDSA signature (r || s || v) over the same digest.
    pub ecdsa_sig: Option<Bytes>,
}

/// Oracle signature scheme used when requesting signatures from the host.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum OracleCipher {
    Ed25519,
    EcdsaSecp256k1,
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

/// Build the canonical Ed25519 oracle signing message: the 32-byte oracle
/// digest followed by a single-byte approval flag (1 for approve, 0 for
/// reject). This binds the signature to both the message and the oracle's
/// vote.
pub fn lvm_digest(msg_hash: &HashBytes, approval: bool) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[..32].copy_from_slice(msg_hash.as_bytes());
    out[32] = if approval { 1 } else { 0 };
    out
}

/// Construct the canonical EVM-side ECDSA digest that ECDSA signers are expected to sign
/// for `OracleTarget::SequenceVM` calls. This digest binds:
/// - the oracle config via `config_hash`,
/// - replay-prevention context (`epoch`, `nonce`),
/// - the call target type: LVM or SequenceVM.
/// - the exact target method + ABI-encoded input.
pub fn evm_digest(header: &OracleHeader, params: &CallParams) -> Hash {
    use alloy_primitives::keccak256;

    let (target_type, target_addr): (u8, Address) = match header.target {
        OracleTarget::Lyquor(_) => (0, Address::ZERO),
        OracleTarget::SequenceVM(addr) => (1, addr),
    };

    let cfg = keccak256(header.config_hash.as_bytes());
    let input = keccak256(params.input.as_ref());
    let selector = keccak256(params.method.as_bytes());

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"lyquor-cert-v1");
    preimage.extend_from_slice(cfg.as_slice());
    preimage.extend_from_slice(&header.epoch.to_be_bytes());
    preimage.extend_from_slice(&header.nonce);
    preimage.push(target_type);
    preimage.extend_from_slice(target_addr.as_slice());
    preimage.extend_from_slice(&selector.as_slice()[..4]);
    preimage.extend_from_slice(input.as_slice());

    let d = keccak256(preimage);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(d.as_slice());
    bytes.into()
}

impl Certificate {
    /// Map signers to committee indices to form bitmap, and serialize signatures.
    pub fn new(digest: HashBytes, sigs: Vec<(OracleSigner, Signature, Option<Bytes>)>, config: &OracleConfig) -> Self {
        // Build map NodeID -> index
        let mut index_of: std::collections::HashMap<NodeID, usize> = std::collections::HashMap::new();
        for (i, s) in config.committee.iter().enumerate() {
            index_of.insert(s.id, i);
        }
        let mut bitmap: u32 = 0;
        let mut out: Vec<u8> = Vec::new();
        for (signer, _ed_sig, evm_sig) in sigs.into_iter() {
            if let Some(i) = index_of.get(&signer.id).copied() {
                if i < 32 {
                    bitmap |= 1u32 << i;
                }
                if let Some(ev) = evm_sig {
                    out.extend_from_slice(&ev);
                }
            }
        }
        Self {
            signer_bitmap: bitmap,
            signatures: out.into(),
            digest,
        }
    }

    /// Fast threshold check using bitmap and config threshold (f + 1).
    pub fn meets_threshold(&self, config: &OracleConfig) -> bool {
        let approved = self.signer_bitmap.count_ones() as usize;
        approved >= config.threshold
    }

    /// Structural verification of the certificate against a given config.
    ///
    /// Note: cryptographic validity of individual signatures is enforced earlier
    /// by the host before this `Certificate` is constructed. So we do not need to
    /// verify again here.
    pub fn verify(&self, config: &OracleConfig) -> bool {
        // Mask out bits that are outside the current committee range.
        let max = config.committee.len().min(32);
        let used_mask: u32 = match max {
            0 => 0,
            32 => u32::MAX,
            n => (1u32 << n) - 1,
        };

        // If there are any bits set beyond the committee length, the certificate is invalid.
        if self.signer_bitmap & !used_mask != 0 {
            return false;
        }

        self.meets_threshold(config)
    }
}

impl OracleCert {
    pub fn verify(&self, caller: &Address, input: Bytes) -> bool {
        // Note: currently we don't bind the certificate to the caller in the LVM as not necessary,
        // but keep the parameter for future tightening if more context is available.
        let _ = caller;

        let Some(inner) = decode_by_fields!(&input, cert: OracleCert, _input_raw: Bytes) else {
            return false;
        };
        if inner.cert != *self {
            return false;
        }

        // If the cert carries a new config, enforce threshold against that config.
        // For non-config-updating certs, we trust the aggregator-side threshold check
        // performed when building `self.cert`.
        if let Some(cfg) = self.new_config.as_ref() {
            self.cert.verify(cfg)
        } else {
            true
        }
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
