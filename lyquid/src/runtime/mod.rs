pub use std::alloc;
pub use std::boxed::Box;
pub use std::vec::Vec;
pub use string_alloc::format_in;

use allocator::Talck;
use alloy_dyn_abi::DynSolValue;
use talc::{ErrOnOom, Span, Talc};

pub use super::*;
mod allocator;
pub mod oracle;
#[doc(hidden)] pub mod syntax;
pub mod upc;

const VOLATILE_SEGMENT_SIZE: usize = VOLATILE_MEMSIZE_IN_MB << 20;
const NETWORK_SEGMENT_SIZE: usize = NETWORK_MEMSIZE_IN_MB << 20;
const INSTANCE_SEGMENT_SIZE: usize = INSTANCE_MEMSIZE_IN_MB << 20;

const VOLATILE_HEADER_SIZE: usize = core::mem::size_of::<VolatileSegmentHeader>();
const NETWORK_HEADER_SIZE: usize = core::mem::size_of::<NetworkSegmentHeader>();
const INSTANCE_HEADER_SIZE: usize = core::mem::size_of::<InstanceSegmentHeader>();

const VOLATILE_HEAP_BASE: usize = LYTEMEM_BASE - VOLATILE_SEGMENT_SIZE;
const VOLATILE_HEADER_BASE: usize = LYTEMEM_BASE - VOLATILE_HEADER_SIZE;
const NETWORK_HEADER_BASE: usize = LYTEMEM_BASE;
const NETWORK_HEAP_BASE: usize = NETWORK_HEADER_BASE + NETWORK_HEADER_SIZE;
const INSTANCE_HEADER_BASE: usize = LYTEMEM_BASE + NETWORK_SEGMENT_SIZE;
const INSTANCE_HEAP_BASE: usize = INSTANCE_HEADER_BASE + INSTANCE_HEADER_SIZE;

#[repr(C)]
struct VolatileSegmentHeader {
    allocator: Talck<ErrOnOom>,
}

#[repr(C)]
struct NetworkSegmentHeader {
    allocator: Talck<ErrOnOom>,
    /// an empty LyteMemory will mark it as "false".
    initialized: bool,
}

#[repr(C)]
struct InstanceSegmentHeader {
    allocator: Talck<ErrOnOom>,
}

#[inline(always)]
fn volatile_segment_header() -> &'static mut VolatileSegmentHeader {
    unsafe { &mut *(VOLATILE_HEADER_BASE as *mut VolatileSegmentHeader) }
}

#[inline(always)]
fn network_segment_header() -> &'static mut NetworkSegmentHeader {
    unsafe { &mut *(NETWORK_HEADER_BASE as *mut NetworkSegmentHeader) }
}

#[inline(always)]
fn instance_segment_header() -> &'static mut InstanceSegmentHeader {
    unsafe { &mut *(INSTANCE_HEADER_BASE as *mut InstanceSegmentHeader) }
}

#[derive(Clone, Default)]
pub struct VolatileAlloc;
pub use instance::Alloc as InstanceAlloc;
pub use network::Alloc as NetworkAlloc;

#[global_allocator]
static ALLOCATOR: VolatileAlloc = VolatileAlloc;

unsafe impl alloc::GlobalAlloc for VolatileAlloc {
    unsafe fn alloc(&self, layout: alloc::Layout) -> *mut u8 {
        unsafe { volatile_segment_header().allocator.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: alloc::Layout) {
        unsafe { volatile_segment_header().allocator.dealloc(ptr, layout) }
    }
}

unsafe impl alloc::Allocator for VolatileAlloc {
    fn allocate(&self, layout: alloc::Layout) -> Result<core::ptr::NonNull<[u8]>, alloc::AllocError> {
        volatile_segment_header().allocator.allocate(layout)
    }

    unsafe fn deallocate(&self, ptr: core::ptr::NonNull<u8>, layout: alloc::Layout) {
        unsafe { volatile_segment_header().allocator.deallocate(ptr, layout) }
    }
}

/// This function should be called to setup the runtime environment before executing any other WASM
/// code.
#[unsafe(no_mangle)]
fn __lyquid_initialize() -> u32 {
    initialize_volatile_heap();
    match initialize_persistent_heap() {
        Some(init) => 0x10 | init,
        None => 0,
    }
}

#[unsafe(no_mangle)]
fn __lyquid_nuke_state() {
    let network_header = network_segment_header();
    network_header.initialized = false;
}

/// Allocate volatile memory.
#[unsafe(no_mangle)]
fn __lyquid_volatile_alloc(size: u32, align: u32) -> *mut u8 {
    use alloc::GlobalAlloc;
    unsafe { ALLOCATOR.alloc(alloc::Layout::from_size_align(size as usize, align as usize).unwrap()) }
}

/// Deallocate volatile memory.
#[unsafe(no_mangle)]
fn __lyquid_volatile_dealloc(base: u32, size: u32, align: u32) {
    use alloc::GlobalAlloc;
    unsafe {
        ALLOCATOR.dealloc(
            base as *mut u8,
            alloc::Layout::from_size_align(size as usize, align as usize).unwrap(),
        )
    }
}

/// Used to force the use of shared memory.
#[unsafe(no_mangle)]
static FORCE_SHARED_MEMORY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Prepare the volatile heap for the execution.
#[inline(always)]
fn initialize_volatile_heap() {
    // always initialize the allocator for volatile memory
    let volatile_header = volatile_segment_header();
    volatile_header.allocator = Talck::new(Talc::new(ErrOnOom));
    unsafe {
        volatile_header
            .allocator
            .lock()
            .claim(Span::from_base_size(
                VOLATILE_HEAP_BASE as *mut u8,
                VOLATILE_SEGMENT_SIZE - VOLATILE_HEADER_SIZE,
            ))
            .ok();
    }
}

/// Prepare the network/instance heap for the execution. Returns `None` upon error. `Some(1)`
/// indicates they were previously initialized.
#[inline(always)]
fn initialize_persistent_heap() -> Option<u32> {
    let network_header = network_segment_header();
    let instance_header = instance_segment_header();

    let ret = if network_header.initialized {
        // already previously initialized
        0
    } else {
        let network_span =
            Span::from_base_size(NETWORK_HEAP_BASE as *mut u8, NETWORK_SEGMENT_SIZE - NETWORK_HEADER_SIZE);
        let instance_span = Span::from_base_size(
            INSTANCE_HEAP_BASE as *mut u8,
            INSTANCE_SEGMENT_SIZE - INSTANCE_HEADER_SIZE - 1,
        ); // minus 1 to avoid 32-bit overflow when Span calculcates the higher end of the span

        network_header.allocator = Talck::new(Talc::new(ErrOnOom));
        instance_header.allocator = Talck::new(Talc::new(ErrOnOom));
        unsafe {
            // otherwise initialize the allocators only once
            network_header.allocator.lock().claim(network_span).ok()?;
            instance_header.allocator.lock().claim(instance_span).ok()?;
        }
        network_header.initialized = true;
        1
    };
    Some(ret)
}

#[doc(hidden)]
pub mod internal {
    use super::*;
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

    pub fn gen_eth_type_string<T: EthABI>(
        form: u8, types: impl Iterator<Item = (Option<String>, bool)>,
    ) -> Option<String> {
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

    pub struct NetworkState {}

    impl NetworkState {
        pub fn new() -> Self {
            Self {}
        }
    }

    // NOTE: limit the implementor of this trait to this LDK crate using sealed trait pattern
    pub(crate) mod sealed {
        pub trait Sealed {}
    }

    /// Contexts that impls this trait are those that support calling `Oracle::certify()`.
    pub trait OracleCertifyContext: sealed::Sealed {}
}

use internal::{OracleCertifyContext, StateAccessor, sealed};

/// Defines a host-side API in WASM environment. It generates a function that directs the flow
/// control to the Lyquor host and returns upon completion.
macro_rules! host_api {
    ($fn:ident($($param:ident: $type:ty),*) -> $rt:ty; $($rest:tt)*) => {
        pub fn $fn($($param:$type),*) -> Result<$rt, $crate::LyquidError> {
            use $crate::lyquor_primitives::decode_object;

            let output_raw = {
                #[link(wasm_import_module = "lyquor_api")]
                unsafe extern "C" {
                    fn $fn(base: u32, len: u32) -> u64;
                }
                // encode input
                let raw = $crate::lyquor_primitives::encode_by_fields!($($param: $type),*);
                // run host-side and locate the returned output in the WASM-allocated memory;
                // host-side will allocate the WASM volatile memory for the result
                unsafe {
                    let output_bundle = $fn(raw.as_ptr() as u32, raw.len() as u32);
                    if output_bundle == 0x0 {
                        return Err($crate::LyquidError::LyquorRuntime("error during the setup of host API environment".to_string()))
                    }
                    core::slice::from_raw_parts(output_bundle as u32 as *mut u8, (output_bundle >> 32) as u32 as usize)
                }
            };
            let output = decode_object::<Result<$rt, $crate::LyquidError>>(output_raw).ok_or($crate::LyquidError::LyquorOutput)?;
            // free the WASM volatile memory allocated by the host
            $crate::runtime::__lyquid_volatile_dealloc(output_raw.as_ptr() as u32, output_raw.len() as u32, 4);
            output
        }

        host_api!($($rest)*);
    };
    ($fn:ident($($param:ident: $type:ty),*); $($rest:tt)*) => {
        host_api!($fn($($param:$type),*) -> (); $($rest)*);
    };
    () => {};
}

/// Host APIs that a Lyquid instance can invoke. The `host_api` macro sets up proper context to
/// make these calls, serialize/deserialize parameters and the result.
pub mod lyquor_api {
    use super::*;
    host_api!(
        state_set(cat: StateCategory, key: Vec<u8>, value: Option<Vec<u8>>);
        state_get(cat: StateCategory, key: Vec<u8>) -> Option<Vec<u8>>;
        version() -> LyquidNumber;
        log(record: LyteLog);
        whoami() -> (NodeID, LyquidID);
        console_output(output: ConsoleSink, s: String);
        universal_procedural_call(target: LyquidID, group: Option<String>, method: String, input: Vec<u8>, nodes: Option<Vec<NodeID>>) -> Vec<u8>;
        inter_lyquid_call(target: LyquidID, method: String, input: Vec<u8>) -> Vec<u8>;
    );
}

/// Print to the console (standard output).
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        lyquor_api::console_output($crate::ConsoleSink::StdOut, format!($($arg)*)).unwrap();
    };
}

/// Print a line to the console (standard output).
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {
        lyquor_api::console_output($crate::ConsoleSink::StdOut, format!($($arg)*) + "\n").unwrap();
    };
}

/// Print to the console (error output).
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {
        lyquor_api::console_output($crate::ConsoleSink::StdErr, format!($($arg)*)).unwrap();
    };
}

/// Print a line to the console (error output).
#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {
        lyquor_api::console_output($crate::ConsoleSink::StdErr, format!($($arg)*) + "\n").unwrap();
    };
}

/// Log a custom event that has happened. (Similar to Solidity's `emit` event, or `log*`
/// instruction in EVM.) **Only usable by network functions.**
#[macro_export]
macro_rules! log {
    ($tag: ident, $v: expr) => {{ lyquor_api::log($crate::LyteLog::new_from_tagged_value(stringify!($tag), $v))? }};
}

/// Initiate a inter-lyquid call. **Only usable by network functions.**
/// FIXME: enforce this at compile time.
#[macro_export]
macro_rules! call {
    (($service: expr).$method :ident($($var:ident: $type:ty = $val: expr),*) -> ($($ovar:ident: $otype:ty),*)) => {
        lyquor_api::inter_lyquid_call(
            $service,
            stringify!($method).to_string().into(),
            Vec::from(&lyquor_primitives::encode_by_fields!($($var: $type = $val),*)[..]),
        ).and_then(|r| lyquor_primitives::decode_by_fields!(&r, $($ovar: $otype),*).ok_or(LyquidError::LyquorOutput))
    };
}

/// Initiate a Universal Procedure Call (UPC). **Only usable by instance functions.**
#[macro_export]
macro_rules! upc {
    (($network: expr).$method: ident[$callee:expr]($($var:ident: $type:ty = $val: expr),*) -> ($($ovar:ident: $otype:ty),*)) => {
        lyquor_api::universal_procedural_call(
            $network,
            None, // TODO: allow user to specify group with upc macro
            stringify!($method).to_string().into(),
            Vec::from(&lyquor_primitives::encode_by_fields!($($var: $type = $val),*)[..]),
            $callee,
        ).and_then(|r| lyquor_primitives::decode_by_fields!(&r, $($ovar: $otype),*).ok_or(LyquidError::LyquorOutput))
    };
}

pub trait EthABI {
    fn type_string() -> Option<String>;
    fn is_scalar() -> bool;
    fn decode(val: DynSolValue) -> Option<Self>
    where
        Self: Sized;
    fn encode(self) -> DynSolValue;
}

impl<T> EthABI for T {
    default fn type_string() -> Option<String> {
        None
    }

    default fn decode(_: DynSolValue) -> Option<Self> {
        None
    }

    default fn is_scalar() -> bool {
        true
    }

    default fn encode(self) -> DynSolValue {
        unreachable!()
    }
}

impl EthABI for U256 {
    fn type_string() -> Option<String> {
        Some("uint256".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 256) => Some(i),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(self, 256)
    }
}

impl EthABI for U128 {
    fn type_string() -> Option<String> {
        Some("uint128".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 128) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(self.to(), 128)
    }
}

impl EthABI for U64 {
    fn type_string() -> Option<String> {
        Some("uint64".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 64) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(self.to(), 64)
    }
}

impl EthABI for u64 {
    fn type_string() -> Option<String> {
        Some("uint64".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 64) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        self.into()
    }
}

impl EthABI for u32 {
    fn type_string() -> Option<String> {
        Some("uint32".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 32) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        self.into()
    }
}

impl EthABI for u16 {
    fn type_string() -> Option<String> {
        Some("uint16".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 16) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        self.into()
    }
}

impl EthABI for u8 {
    fn type_string() -> Option<String> {
        Some("uint8".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 8) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        self.into()
    }
}

impl EthABI for bool {
    fn type_string() -> Option<String> {
        Some("bool".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        self.into()
    }
}

impl<T: EthABI> EthABI for Vec<T> {
    fn type_string() -> Option<String> {
        T::type_string().map(|s| format!("{}[]", s))
    }

    fn is_scalar() -> bool {
        false
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Array(v) => v.into_iter().map(|v| T::decode(v)).collect(),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Array(self.into_iter().map(|e| e.encode()).collect())
    }
}

impl<T: EthABI, const N: usize> EthABI for [T; N] {
    fn type_string() -> Option<String> {
        T::type_string().map(|s| format!("{}[{N}]", s))
    }

    fn is_scalar() -> bool {
        false
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::FixedArray(v) => v
                .into_iter()
                .map(|v| T::decode(v))
                .collect::<Option<Vec<T>>>()
                .and_then(|v| v.try_into().ok()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::FixedArray(self.into_iter().map(|e| e.encode()).collect())
    }
}

impl EthABI for String {
    fn type_string() -> Option<String> {
        Some("string".into())
    }

    fn is_scalar() -> bool {
        false
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::String(s) => Some(s.into()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::String(self.into())
    }
}

impl EthABI for Address {
    fn type_string() -> Option<String> {
        Some("address".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Address(a) => Some(a),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Address(self)
    }
}

impl EthABI for LyquidID {
    fn type_string() -> Option<String> {
        Some("address".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Address(a) => Some(Self(a.0.into())),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Address(self.0.into())
    }
}

impl EthABI for RequiredLyquid {
    fn type_string() -> Option<String> {
        Some("address".into())
    }

    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Address(a) => Some(Self(a.0.0.into())),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Address(self.0.0.into())
    }
}

pub use hashbrown;
type HashMap_<K, V, A> = hashbrown::HashMap<K, V, ahash::RandomState, A>;
type HashSet_<K, A> = hashbrown::HashSet<K, ahash::RandomState, A>;

pub type HashMap<K, V> = volatile::HashMap<K, V>;
pub type HashSet<K> = volatile::HashSet<K>;
pub use volatile::{new_hashmap, new_hashset};

macro_rules! gen_container_types {
    ($alloc: tt) => {
        pub type Box<T> = super::Box<T, $alloc>;
        pub fn new_vec<T>() -> Vec<T> {
            Vec::new_in($alloc)
        }

        pub type Vec<T> = super::Vec<T, $alloc>;
        pub fn new_box<T>(v: T) -> Box<T> {
            Box::new_in(v, $alloc)
        }

        pub type String = string_alloc::String<$alloc>;
        pub fn new_string() -> String {
            String::new_in($alloc)
        }

        pub type VecDeque<T> = std::collections::VecDeque<T, $alloc>;
        pub fn new_vecdeque<T>() -> VecDeque<T> {
            VecDeque::new_in($alloc)
        }

        pub type LinkedList<T> = std::collections::LinkedList<T, $alloc>;
        pub fn new_linkedlist<T>() -> LinkedList<T> {
            LinkedList::new_in($alloc)
        }

        pub type HashMap<K, V> = super::HashMap_<K, V, $alloc>;
        pub fn new_hashmap<K, V>() -> HashMap<K, V> {
            HashMap::with_hasher_in(ahash::RandomState::with_seed(0), $alloc)
        }

        pub type HashSet<K> = super::HashSet_<K, $alloc>;
        pub fn new_hashset<K>() -> HashSet<K> {
            HashSet::with_hasher_in(ahash::RandomState::with_seed(0), $alloc)
        }

        pub type BTreeMap<K, V> = std::collections::BTreeMap<K, V, $alloc>;
        pub fn new_btreemap<K, V>() -> BTreeMap<K, V> {
            BTreeMap::new_in($alloc)
        }

        pub type BTreeSet<K> = std::collections::BTreeSet<K, $alloc>;
        pub fn new_btreeset<K>() -> BTreeSet<K> {
            BTreeSet::new_in($alloc)
        }

        pub type BinaryHeap<T> = std::collections::BinaryHeap<T, $alloc>;
        pub fn new_binaryheap<T: Ord>() -> BinaryHeap<T> {
            BinaryHeap::new_in($alloc)
        }
    };
}

/// Format a [network::String] (similar to `format!` but the resulting String is allocated in network state).
#[macro_export]
macro_rules! network_format {
	($($arg:tt)*) => {{
		$crate::runtime::format_in!($crate::runtime::NetworkAlloc, $($arg)*)
	}}
}

/// Format an [instance::String] (similar to `format!` but the resulting String is allocated in instance state).
#[macro_export]
macro_rules! instance_format {
	($($arg:tt)*) => {{
		$crate::runtime::format_in!($crate::runtime::InstanceAlloc, $($arg)*)
	}}
}

/// Network persistent state memory allocator and standard containers.
pub mod network {
    use super::*;

    /// Allocator type that Lyquid developer should use when defining a type that needs to make
    /// dynamic allocation.
    ///
    /// In most cases, you don't need to use this, because common containers are already
    /// re-exported to make sure they use the proper allocator. You can write somethng like:
    /// `network::HashMap<Address, network::Vec<u8>>`, which maps from an address to a vector of
    /// bytes (note that you still need to ensure all containers are from the same storage category,
    /// `network::` in this case).
    ///
    /// One should always ensure any customized type for an *network variable*
    /// is entirely allocated with this allocator, otherwise there could be dangling poiners and
    /// corruption. In short, all data in a category should always directly or indirectly reference
    /// to those in the *same* category, so it's invalid to write something like `network::Vec<instance::Vec<u8>>`.
    ///
    /// For example, `MyContainer<MyOtherContainer<T, Alloc>, Alloc>` describes a customized
    /// container implementation by the developer, where the same [Alloc] is used for all its
    /// possible indirections (the inner `MyOtherContainer` also use the same allocator for heap
    /// allocation).
    ///
    /// This opaque type prevents the developer from mixing allocators in different categories.
    #[derive(Clone, Default)]
    pub struct Alloc;

    unsafe impl alloc::Allocator for Alloc {
        fn allocate(&self, layout: alloc::Layout) -> Result<core::ptr::NonNull<[u8]>, alloc::AllocError> {
            network_segment_header().allocator.allocate(layout)
        }

        unsafe fn deallocate(&self, ptr: core::ptr::NonNull<u8>, layout: alloc::Layout) {
            unsafe { network_segment_header().allocator.deallocate(ptr, layout) }
        }
    }

    gen_container_types!(Alloc);

    pub use oracle::Oracle;
}

/// Instance persistent state memory allocator and standard containers.
pub mod instance {
    use super::*;

    /// Allocator type that Lyquid developer should use when defining a type that needs to make
    /// dynamic allocation.
    ///
    /// In most cases, you don't need to use this, because common containers are already
    /// re-exported to make sure they use the proper allocator. You can write somethng like:
    /// `network::HashMap<Address, network::Vec<u8>>`, which maps from an address to a vector of
    /// bytes (note that you still need to ensure all containers are from the same storage category,
    /// `network::` in this case).
    ///
    /// One should always ensure any customized type for an *instance variable*
    /// is entirely allocated with this allocator, otherwise there could be dangling poiners and
    /// corruption. In short, all data in a category should always directly or indirectly reference
    /// to those in the *same* category, so it's invalid to write something like `network::Vec<instance::Vec<u8>>`.
    ///
    /// For example, `MyContainer<MyOtherContainer<T, Alloc>, Alloc>` describes a customized
    /// container implementation by the developer, where the same [Alloc] is used for all its
    /// possible indirections (the inner `MyOtherContainer` also use the same allocator for heap
    /// allocation).
    ///
    /// This opaque type prevents the developer from mixing allocators in different categories.
    #[derive(Clone, Default)]
    pub struct Alloc;

    unsafe impl alloc::Allocator for Alloc {
        fn allocate(&self, layout: alloc::Layout) -> Result<core::ptr::NonNull<[u8]>, alloc::AllocError> {
            instance_segment_header().allocator.allocate(layout)
        }

        unsafe fn deallocate(&self, ptr: core::ptr::NonNull<u8>, layout: alloc::Layout) {
            unsafe { instance_segment_header().allocator.deallocate(ptr, layout) }
        }
    }

    gen_container_types!(Alloc);
}

pub mod volatile {
    use super::VolatileAlloc;
    gen_container_types!(VolatileAlloc);
}

pub struct RwLock<T: ?Sized>(std::sync::RwLock<T>);

impl<T> RwLock<T> {
    pub fn new(inner: T) -> Self {
        Self(std::sync::RwLock::new(inner))
    }

    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.0.read().unwrap()
    }

    pub fn write(&mut self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.0.write().unwrap()
    }
}

impl<T> std::ops::Deref for RwLock<T> {
    type Target = std::sync::RwLock<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Mutex<T: ?Sized>(std::sync::Mutex<T>);

impl<T> Mutex<T> {
    pub fn new(inner: T) -> Self {
        Self(std::sync::Mutex::new(inner))
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}

impl<T> std::ops::Deref for Mutex<T> {
    type Target = std::sync::Mutex<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Immutable<T>(T);

impl<T> Immutable<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> std::ops::Deref for Immutable<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

pub struct Mutable<T>(T);

impl<T> Mutable<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> std::ops::Deref for Mutable<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Mutable<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Read/write the network state variables, which is allowed for network funcs.
pub struct NetworkContextImpl<S>
where
    S: StateAccessor,
{
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub network: Mutable<S>,
}

impl<S> NetworkContextImpl<S>
where
    S: StateAccessor,
{
    pub fn new(ctx: CallContext) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Mutable::new(S::new()?),
        })
    }
}

/// Read-only wrapper for network state variables.
pub struct ImmutableNetworkContextImpl<S>
where
    S: StateAccessor,
{
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub network: Immutable<S>,
}

impl<S> ImmutableNetworkContextImpl<S>
where
    S: StateAccessor,
{
    pub fn new(ctx: CallContext) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new()?),
        })
    }
}

/// Read/write the instance state variables, which is allowed for instance funcs.
/// Also allowed to read the network state variables.
pub struct InstanceContextImpl<S, I>
where
    S: StateAccessor,
    I: StateAccessor,
{
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub network: Immutable<S>,
    pub instance: Mutable<I>,
}

impl<S, I> InstanceContextImpl<S, I>
where
    S: StateAccessor,
    I: StateAccessor,
{
    pub fn new(ctx: CallContext) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new()?),
            instance: Mutable::new(I::new()?),
        })
    }
}

impl<S: StateAccessor, I: StateAccessor> sealed::Sealed for InstanceContextImpl<S, I> {}
impl<S: StateAccessor, I: StateAccessor> OracleCertifyContext for InstanceContextImpl<S, I> {}

/// Read-only wrapper for state variables.
pub struct ImmutableInstanceContextImpl<S, I>
where
    S: StateAccessor,
    I: StateAccessor,
{
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub network: Immutable<S>,
    pub instance: Immutable<I>,
}

impl<S, I> ImmutableInstanceContextImpl<S, I>
where
    S: StateAccessor,
    I: StateAccessor,
{
    pub fn new(ctx: CallContext) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new()?),
            instance: Immutable::new(I::new()?),
        })
    }
}

impl<S: StateAccessor, I: StateAccessor> sealed::Sealed for ImmutableInstanceContextImpl<S, I> {}
impl<S: StateAccessor, I: StateAccessor> OracleCertifyContext for ImmutableInstanceContextImpl<S, I> {}
