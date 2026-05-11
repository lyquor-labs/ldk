use super::oracle::{OracleDest, OracleSrc};
use super::{__lyquid_volatile_alloc, __lyquid_volatile_dealloc, lyquor_api};
use super::{GuestSlice, GuestUsize, NativeGuestAbi};
use crate::{LyquidError, LyquidResult};
use lyquor_primitives::StateCategory;

pub use lyquid_proc::*;

pub struct HostInput(&'static [u8]);

impl Drop for HostInput {
    fn drop(&mut self) {
        let base = self.0.as_ptr() as GuestUsize;
        let len = self.0.len() as GuestUsize;
        // deallocate the host-allocated input
        __lyquid_volatile_dealloc(base, len, <NativeGuestAbi as crate::mem::Guest>::USIZE_ALIGN_VALUE);
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
    pub unsafe fn new(base: GuestUsize, len: GuestUsize) -> Self {
        unsafe { Self(core::slice::from_raw_parts(base as *mut u8, len as usize)) }
    }
}

/// Abort the current network-slot execution by forcing a guest trap.
///
/// `call!` uses this to enforce strict atomic inter-call semantics: once an
/// inter-lyquid call fails, guest code must not continue running and the
/// current sequenced slot should unwind as a single reverted batch.
#[cold]
#[inline(never)]
pub fn abort_atomic_inter_call(err: LyquidError) -> ! {
    panic!("atomic inter-call aborted: {err}")
}

pub struct HostOutput {
    block: GuestUsize,
    slice: GuestSlice,
}

impl HostOutput {
    #[inline(always)]
    fn header_align() -> GuestUsize {
        crate::mem::Slice::<NativeGuestAbi>::align() as GuestUsize
    }

    #[inline(always)]
    fn block_size_for(len: GuestUsize) -> GuestUsize {
        (crate::mem::Slice::<NativeGuestAbi>::size() + len as usize) as GuestUsize
    }

    pub unsafe fn read(block: GuestUsize) -> LyquidResult<Self> {
        if block == 0 as GuestUsize {
            return Err(LyquidError::LyquorRuntime(
                "error during the setup of host API environment".to_string(),
            ));
        }
        Ok(Self {
            block,
            slice: unsafe { (block as *const GuestSlice).read() },
        })
    }

    pub unsafe fn as_slice<'a>(&'a self) -> &'a [u8] {
        if self.slice.len == 0 as GuestUsize {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.slice.base as *const u8, self.slice.len as usize) }
        }
    }

    #[inline(always)]
    fn block_size(&self) -> GuestUsize {
        Self::block_size_for(self.slice.len)
    }
}

impl Drop for HostOutput {
    fn drop(&mut self) {
        __lyquid_volatile_dealloc(self.block, self.block_size(), Self::header_align());
    }
}

#[inline]
pub fn output_to_host(output: &[u8]) -> GuestUsize {
    let output_len = output.len() as GuestUsize;
    let block_size = HostOutput::block_size_for(output_len);
    let block = __lyquid_volatile_alloc(block_size, HostOutput::header_align());
    if block == 0 as GuestUsize {
        return 0 as GuestUsize;
    }
    let output_base = if output.is_empty() {
        0 as GuestUsize
    } else {
        (block as usize + crate::mem::Slice::<NativeGuestAbi>::size()) as GuestUsize
    };

    unsafe {
        (block as *mut GuestSlice).write(GuestSlice {
            base: output_base,
            len: output_len,
        });
        if !output.is_empty() {
            core::slice::from_raw_parts_mut(output_base as *mut u8, output.len()).copy_from_slice(output);
        }
    }
    block
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

pub struct BuiltinNetworkState {
    oracle_dest: super::HashMap<String, OracleDest>,
    oracle_src: super::HashMap<String, OracleSrc>,
}

impl BuiltinNetworkState {
    pub fn new() -> Self {
        Self {
            oracle_dest: super::new_hashmap(),
            oracle_src: super::new_hashmap(),
        }
    }

    /// Get (and create if missing) the destination-chain oracle topic state for the given topic key.
    pub fn oracle_dest(&mut self, topic: &str) -> &mut OracleDest {
        self.oracle_dest
            .entry(topic.to_string())
            .or_insert_with(OracleDest::default)
    }

    pub fn oracle_dest_epoch_info(&self, topic: &str, full_config: bool) -> lyquor_primitives::oracle::OracleEpochInfo {
        match self.oracle_dest.get(topic) {
            Some(dest) => {
                let config_hash = dest.get_config_hash().clone();
                lyquor_primitives::oracle::OracleEpochInfo {
                    epoch: dest.get_epoch(),
                    change_count: dest.get_change_count(),
                    config: if full_config && config_hash != [0; 32].into() {
                        Some(dest.get_config())
                    } else {
                        None
                    },
                    config_hash,
                }
            }
            None => lyquor_primitives::oracle::OracleEpochInfo {
                epoch: 0,
                config_hash: [0; 32].into(),
                change_count: 0,
                config: None,
            },
        }
    }

    pub fn oracle_src(&self, topic: &str) -> Option<&OracleSrc> {
        self.oracle_src.get(topic)
    }

    pub fn oracle_src_mut(&mut self, topic: &str) -> &mut OracleSrc {
        self.oracle_src
            .entry(topic.to_string())
            .or_insert_with(|| OracleSrc::new(topic))
    }
}

pub struct BuiltinInstanceState;

impl BuiltinInstanceState {
    pub fn new() -> Self {
        Self
    }
}

/// Returns built-in instance state initialized by runtime bootstrap.
pub(crate) fn builtin_instance_state() -> &'static mut BuiltinInstanceState {
    let internal_pa = PrefixedAccess::new(Vec::from(crate::INTERNAL_STATE_PREFIX));
    let Some(addr) = internal_pa
        .get(StateCategory::Instance, "instance".as_bytes())
        .ok()
        .flatten()
        .and_then(|bytes| bytes.try_into().ok())
    else {
        panic!("NEAT: failed to access builtin instance state.");
    };
    let addr = u64::from_be_bytes(addr);
    unsafe { &mut *(addr as *mut BuiltinInstanceState) }
}

/// Returns built-in network state initialized by runtime bootstrap.
pub(crate) fn builtin_network_state() -> &'static mut BuiltinNetworkState {
    let internal_pa = PrefixedAccess::new(Vec::from(crate::INTERNAL_STATE_PREFIX));
    let Some(addr) = internal_pa
        .get(StateCategory::Network, "network".as_bytes())
        .ok()
        .flatten()
        .and_then(|bytes| bytes.try_into().ok())
    else {
        panic!("NEAT: failed to access builtin network state.");
    };
    let addr = u64::from_be_bytes(addr);
    unsafe { &mut *(addr as *mut BuiltinNetworkState) }
}
