use crate::hex::{self, FromHex};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::fmt;
use std::hash;

/// The ID of a node in the network.
/// The ID is 35 bytes long, the first 32 bytes are the node's ed25519 public key,
/// and the following 2 bytes are checksums, the last byte is the version number (1)
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Hash)]
pub struct NodeID(pub [u8; 32], pub [u8; 3]);

impl NodeID {
    pub fn new(id: [u8; 32]) -> Self {
        let mut checksum = [0; 3];
        // Calculate SHA3-256 hash of the ID
        let mut hash = sha3::Sha3_256::default();
        hash.update(&id);
        let hash = hash.finalize();
        // Take the first two bytes of the hash as the checksum
        checksum[0] = hash[0];
        checksum[1] = hash[1];
        checksum[2] = 0; // v0
        Self(id, checksum)
    }
}

impl From<u64> for NodeID {
    fn from(x: u64) -> NodeID {
        let mut id = [0; 32];
        id[32 - 8..].copy_from_slice(&x.to_be_bytes());
        NodeID::new(id)
    }
}

impl From<ed25519_compact::PublicKey> for NodeID {
    fn from(pk: ed25519_compact::PublicKey) -> Self {
        NodeID::new(*pk)
    }
}

impl NodeID {
    const ALPHABET: base32::Alphabet = base32::Alphabet::Rfc4648Lower { padding: false };

    pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().unwrap())
    }

    pub fn as_ed25519_public_key(&self) -> ed25519_compact::PublicKey {
        ed25519_compact::PublicKey::from_slice(&self.0).unwrap()
    }

    pub fn as_dns_label(&self) -> String {
        // Combine the ID and checksum into a single array
        let mut id: [u8; 35] = [0; 35];
        id[..32].copy_from_slice(&self.0);
        id[32..].copy_from_slice(&self.1);
        base32::encode(Self::ALPHABET, &id)
    }
}

impl fmt::Display for NodeID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Node-{}", self.as_dns_label())
    }
}

impl fmt::Debug for NodeID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}

impl From<NodeID> for [u8; 32] {
    fn from(val: NodeID) -> Self {
        val.0
    }
}

impl From<[u8; 32]> for NodeID {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl<'a> TryFrom<&'a [u8]> for NodeID {
    type Error = IDError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(IDError::Length);
        }

        let mut id = [0; 32];
        id.copy_from_slice(bytes);
        Ok(Self::new(id))
    }
}

impl FromHex for NodeID {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::from_hex(hex)?;
        Ok(Self::new(bytes))
    }
}

impl AsRef<[u8]> for NodeID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct LyquidID(pub [u8; 32]);

impl Serialize for LyquidID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for LyquidID {
    fn deserialize<D>(deserializer: D) -> Result<LyquidID, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <&str as Deserialize>::deserialize(deserializer)?;
            s.parse().map_err(|e| serde::de::Error::custom(format!("{e:?}")))
        } else {
            let arr = <[u8; 32] as Deserialize>::deserialize(deserializer)?;
            Ok(LyquidID(arr))
        }
    }
}

impl From<LyquidID> for [u8; 32] {
    fn from(val: LyquidID) -> Self {
        val.0
    }
}

impl From<[u8; 32]> for LyquidID {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<u64> for LyquidID {
    fn from(x: u64) -> Self {
        let mut id = [0; 32];
        id[32 - 8..].copy_from_slice(&x.to_be_bytes());
        Self(id)
    }
}

impl fmt::Display for LyquidID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Lyquid-{}", cb58::cb58_encode(self.0))
    }
}

impl fmt::Debug for LyquidID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}

impl LyquidID {
    pub fn readable_short(&self) -> String {
        let s = self.to_string();
        format!("{}..{}", &s[..15], &s[s.len() - 8..])
    }
}

impl FromHex for LyquidID {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::from_hex(hex)?;
        Ok(Self(bytes))
    }
}

#[derive(Debug)]
pub enum IDError {
    Prefix,
    CB58,
    Length,
}

impl std::str::FromStr for LyquidID {
    type Err = IDError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const PREFIX: &str = "Lyquid-";
        if s.len() < PREFIX.len() || &s[..PREFIX.len()] != PREFIX {
            return Err(IDError::Prefix);
        }
        let bytes = cb58::cb58_decode(&s[PREFIX.len()..]).ok_or(IDError::CB58)?;
        Ok(LyquidID(bytes.try_into().map_err(|_| IDError::Length)?))
    }
}

impl AsRef<[u8]> for LyquidID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Debug)]
/// The verison number that uniquely identifies (and determines) the state of service variables.
pub struct LyquidNumber {
    /// The version number for the Lyquid service code image.
    pub image: u32,
    /// The version number for the Lyquid service variables.
    pub var: u32,
}

impl fmt::Display for LyquidNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LyquidNumber(image={}, var={})", self.image, self.var)
    }
}

impl LyquidNumber {
    pub const ZERO: Self = LyquidNumber { image: 0, var: 0 };
}

impl From<u64> for LyquidNumber {
    fn from(x: u64) -> Self {
        Self {
            image: (x >> 32) as u32,
            var: x as u32,
        }
    }
}

impl From<&LyquidNumber> for u64 {
    fn from(n: &LyquidNumber) -> u64 {
        ((n.image as u64) << 32) | n.var as u64
    }
}

impl From<LyquidNumber> for u64 {
    fn from(n: LyquidNumber) -> u64 {
        (&n).into()
    }
}

pub trait ID32: hash::Hash + Eq + Into<[u8; 32]> + From<[u8; 32]> + Clone + Send + Sync {}

impl<T: hash::Hash + Eq + Into<[u8; 32]> + From<[u8; 32]> + Clone + Send + Sync> ID32 for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::KeyPair;

    fn check_id32<T: ID32>() {}

    #[test]
    fn test_id32() {
        check_id32::<NodeID>();
        check_id32::<LyquidID>();
    }

    #[test]
    fn test_hex() {
        let kp = KeyPair::from_seed([42u8; 32].into());
        let id = NodeID::from(kp.pk);
        let hex = hex::encode(*kp.pk);
        let decoded_id = NodeID::from_hex(&hex).unwrap();
        assert_eq!(id, decoded_id);
        assert_eq!(hex, "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61");
        assert_eq!(
            id.to_string(),
            "Node-df7wwi7bnsctfrvlza4pvtk6u6e34ddwwkjagnadtp5iwpjwrvqvfyya"
        );
        assert_eq!(
            id.as_dns_label(),
            "df7wwi7bnsctfrvlza4pvtk6u6e34ddwwkjagnadtp5iwpjwrvqvfyya"
        );
    }
}
