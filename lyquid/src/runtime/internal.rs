use super::*;
use oracle::OracleDest;

pub use lyquid_proc::*;

pub struct HostInput(&'static [u8]);

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

pub fn eth_func_type_string<T: EthABI>(form: u8, params: impl Iterator<Item = Option<DynSolType>>) -> Option<String> {
    let loc = match form {
        0 => None,
        1 => Some("calldata"),
        _ => Some("memory"),
    };

    // assemble eth abi string for each parameter
    let params = params
        .map(|t| t.map(|t| sol_type_name_with_location_keyword(&t, loc)))
        .collect::<Option<Vec<String>>>()?;
    match form {
        0x0 => Some(format!("({})", params.join(","))),
        _ => {
            // also check if the output impl EthABI
            let ret = T::return_type_string()?;
            Some(format!("({}) returns ({})", params.join(", "), ret))
        }
    }
}

pub struct BuiltinNetworkState {
    oracle: super::HashMap<String, OracleDest>,
}

impl BuiltinNetworkState {
    pub fn new() -> Self {
        Self {
            oracle: super::new_hashmap(),
        }
    }

    /// Get (and create if missing) the destination-chain oracle topic state for the given topic key.
    pub fn oracle_dest(&mut self, topic: &'static str) -> &mut OracleDest {
        self.oracle.entry(topic.to_string()).or_insert_with(OracleDest::default)
    }
}

// NOTE: limit the implementor of this trait to this LDK crate using sealed trait pattern
// The extra sealed mod is used as a visibility trick.
pub(crate) mod sealed {
    pub trait Sealed {}
}

impl<S: StateAccessor, I: StateAccessor> sealed::Sealed for InstanceContextImpl<S, I> {}
impl<S: StateAccessor, I: StateAccessor> sealed::Sealed for ImmutableInstanceContextImpl<S, I> {}
