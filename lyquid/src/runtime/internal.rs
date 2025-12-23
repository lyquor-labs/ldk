use super::*;
use lyquor_primitives::{HashBytes, OracleConfig};
pub struct HostInput(&'static [u8]);
pub use lyquid_proc::*;

impl Drop for HostInput {
    fn drop(&mut self) {
        let base = self.0.as_ptr() as u32;
        let len = self.0.len() as u32;
        // deallocate the host-allocated input
        __lyquid_volatile_dealloc(base, len, 4);
    }
}

impl core::ops::Deref for HostInput {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0
    }
}

impl HostInput {
    #[inline(always)]
    pub unsafe fn new(base: u32, len: u32) -> Self {
        unsafe { Self(core::slice::from_raw_parts(base as *mut u8, len as usize)) }
    }
}

#[inline]
pub fn output_to_host(output: &[u8]) -> u64 {
    let output_len = output.len() as u32;
    let output_base = unsafe {
        // allocate output
        let ptr = __lyquid_volatile_alloc(output_len, 4);
        core::slice::from_raw_parts_mut(ptr as *mut u8, output_len as usize).copy_from_slice(&output);
        ptr
    } as u32;
    ((output_len as u64) << 32) | output_base as u64
}

pub trait StateAccessor {
    fn new() -> Result<Self, LyquidError>
    where
        Self: Sized;
}

/// A low-cost wrapper that applies the same prefix to low-level state access through `lyquor_api`.
/// Lyquid developer do not need to use this, as it is used by the macro-generated code when a
/// developer accesses variables. Directly using this low-level interface can interfere with the
/// variable bookkeeping. Make sure you understand what key you use before the access.
pub struct PrefixedAccess<P: AsRef<[u8]>>(P);

impl<P: AsRef<[u8]>> PrefixedAccess<P> {
    pub fn new(prefix: P) -> Self {
        Self(prefix)
    }

    #[inline(always)]
    fn add_prefix(&self, key: &[u8]) -> Vec<u8> {
        let mut prefixed = Vec::from(self.0.as_ref());
        prefixed.extend_from_slice(key);
        prefixed
    }

    #[inline(always)]
    pub fn set(&self, cat: StateCategory, key: &[u8], value: &[u8]) -> LyquidResult<()> {
        lyquor_api::state_set(cat, self.add_prefix(key), Some(Vec::from(value)))
    }

    #[inline(always)]
    pub fn get(&self, cat: StateCategory, key: &[u8]) -> LyquidResult<Option<Vec<u8>>> {
        lyquor_api::state_get(cat, self.add_prefix(key))
    }
}

impl PrefixedAccess<Vec<u8>> {
    /// Extend the builtin prefix.
    pub fn extend(&self, suffix: &[u8]) -> PrefixedAccess<Vec<u8>> {
        let mut prefix = self.0.clone();
        prefix.extend(suffix);
        Self(prefix)
    }
}

pub fn gen_eth_type_string<T: EthABI>(form: u8, types: impl Iterator<Item = (Option<String>, bool)>) -> Option<String> {
    // assemble eth abi string for each parameter
    let type_parts = types
        .map(|(s, scalar)| {
            s.map(|mut s| {
                if !scalar {
                    match form {
                        0x0 => (),
                        0x1 => s.push_str(" calldata"),
                        _ => s.push_str(" memory"),
                    }
                }
                s
            })
        })
        .collect::<Option<Vec<String>>>()?;
    match form {
        0x0 => Some(format!("({})", type_parts.join(","))),
        _ => {
            // also check if the output impl EthABI
            let rt_part = match T::type_string() {
                Some(mut s) => {
                    if !T::is_scalar() {
                        match form {
                            0x0 => (),
                            _ => s.push_str(" memory"),
                        }
                    }
                    s
                }
                None => String::new(),
            };
            Some(format!("({}) returns ({})", type_parts.join(", "), rt_part))
        }
    }
}

pub struct BuiltinNetworkState {
    oracle: super::network::HashMap<String, OracleDest>,
}

/// Per-topic destination-chain oracle state.
pub struct OracleDest {
    // The following states are used for certificate verification.
    // Active oracle config for the topic.
    config: OracleConfig,
    // Hash of _config for the topic.
    config_hash: HashBytes,
    // The following variables are used to ensure a certified call is at most invoked once.
    // Epoch number.
    epoch: u32,
    used_nonce: super::network::HashSet<Hash>,
}

impl Default for OracleDest {
    fn default() -> Self {
        Self {
            config: OracleConfig {
                threshold: 0,
                committee: Vec::new(),
            },
            config_hash: [0; 32].into(),
            epoch: 0,
            used_nonce: super::network::new_hashset(),
        }
    }
}

impl OracleDest {
    const MAX_NONCE_PER_EPOCH: usize = 1_000_000;

    pub fn get_epoch(&self) -> u32 {
        self.epoch
    }

    pub fn get_config_hash(&self) -> &HashBytes {
        &self.config_hash
    }

    fn update_config(&mut self, config: OracleConfig, config_hash: HashBytes) -> bool {
        if config.committee.is_empty() {
            // No signers.
            return false;
        }
        if config.committee.len() > u16::MAX as usize {
            // Too many signers.
            return false;
        }
        if config.threshold == 0 || config.threshold > config.committee.len() {
            // Invalid threshold.
            return false;
        }
        self.config = config;
        self.config_hash = config_hash;
        true
    }

    /// Record a nonce in the given epoch. Returns false if invalid.
    fn record_nonce(&mut self, epoch: u32, nonce: Hash) -> bool {
        if epoch < self.epoch {
            // Stale epoch.
            return false;
        }

        // Enter a new epoch if higher.
        if epoch > self.epoch {
            if self.used_nonce.len() < Self::MAX_NONCE_PER_EPOCH {
                // Epoch advanced too early.
                return false;
            }
            self.epoch = epoch;
            self.used_nonce.clear();
        }

        if self.used_nonce.len() >= Self::MAX_NONCE_PER_EPOCH {
            // Epoch full.
            return false;
        }

        // Mark the nonce as used.
        self.used_nonce.insert(nonce)
        // false if Nonce is used.
    }

    pub fn verify(&mut self, me: LyquidID, params: lyquor_primitives::CallParams, oc: OracleCert) -> bool {
        // Ensure the certificate targets this Lyquid
        match oc.header.target {
            lyquor_primitives::OracleTarget::LVM(id) => {
                if id != me {
                    // Target mismatch (possible Lyquid-level replay attempt).
                    return false;
                }
            }
            _ => return false,
        }

        // Ensure the preimage matches the signed digest.
        let hash: HashBytes = lyquor_primitives::OraclePreimage {
            header: oc.header,
            params,
            approval: true,
        }
        .to_hash()
        .into();
        if hash != oc.cert.digest {
            // Mismatch digest.
            return false;
        }

        // Verify the validity of the OracleCert.
        if !oc.verify(&self.config, &self.config_hash) {
            // Invalid call certificate.
            return false;
        }

        if let Some(config) = oc.new_config {
            // This certificate also piggybacks a config update (that's signed
            // together with the call payload, and therefore has also been
            // validated). Let's first update the config because it is used for
            // this call and future calls, until a later update.
            if !self.update_config(config, oc.header.config_hash) {
                return false;
            }
        }

        // Prevent the call from being used again.
        self.record_nonce(oc.header.epoch, oc.header.nonce.into())
    }
}

impl BuiltinNetworkState {
    pub fn new() -> Self {
        Self {
            oracle: super::network::new_hashmap(),
        }
    }

    /// Get (and create if missing) the destination-chain oracle topic state for the given topic key.
    pub fn oracle_dest(&mut self, topic: &'static str) -> &mut OracleDest {
        self.oracle.entry(topic.to_string()).or_insert_with(OracleDest::default)
    }
}

// NOTE: limit the implementor of this trait to this LDK crate using sealed trait pattern
pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Contexts that impls this trait are those that support calling `Oracle::certify()`.
pub trait OracleCertifyContext: sealed::Sealed {
    fn get_lyquid_id(&self) -> LyquidID;
    fn get_node_id(&self) -> NodeID;
}
