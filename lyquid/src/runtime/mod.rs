mod allocator;
#[doc(hidden)] pub mod ethabi;
#[doc(hidden)] pub mod internal;
pub mod oracle;
pub mod prelude;
#[doc(hidden)] pub mod sync;
#[doc(hidden)] pub mod syntax;
pub mod upc;

use std::alloc;

use allocator::Talck;
use lyquor_primitives::{Cipher, ConsoleSink, LyteLog, StateCategory};
use talc::{ErrOnOom, Span, Talc};

use super::http;
use super::{
    CallContext, INSTANCE_MEMSIZE_IN_MB, LYTEMEM_BASE, LyquidResult, NETWORK_MEMSIZE_IN_MB, VOLATILE_MEMSIZE_IN_MB,
};
use internal::StateAccessor;
use prelude::*;

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
    /// Used by the global allocator to tell which heap to use for (de)allocation.
    /// 0x0 -- volatile
    /// 0x1 -- instance
    /// 0x2 -- network
    category: u8,
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

#[inline(always)]
pub unsafe fn set_allocator_category(category: u8) {
    volatile_segment_header().category = category;
}

#[derive(Clone, Default)]
struct MuxAlloc;

#[global_allocator]
static ALLOCATOR: MuxAlloc = MuxAlloc;

impl MuxAlloc {
    #[inline(always)]
    unsafe fn zero_memory(ptr: *mut u8, layout: alloc::Layout) {
        unsafe {
            ptr.write_bytes(0, layout.size());
            std::hint::black_box(ptr);
        }
    }
}

unsafe impl alloc::GlobalAlloc for MuxAlloc {
    unsafe fn alloc(&self, layout: alloc::Layout) -> *mut u8 {
        let header = volatile_segment_header();
        unsafe {
            match header.category {
                0x1 => &instance_segment_header().allocator,
                0x2 => &network_segment_header().allocator,
                _ => &volatile_segment_header().allocator,
                // default to volatile until the allocator category is set
            }
            .alloc(layout)
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: alloc::Layout) {
        let header = volatile_segment_header();
        // Zeroing the space to avoid DB writes in page diffing.
        unsafe {
            Self::zero_memory(ptr, layout);

            match header.category {
                0x1 => &instance_segment_header().allocator,
                0x2 => &network_segment_header().allocator,
                _ => &volatile_segment_header().allocator,
            }
            .dealloc(ptr, layout)
        }
    }
}

/// This function should be called to setup the runtime environment before executing any other WASM
/// code, **every time** after the memory is created.
#[unsafe(no_mangle)]
fn __lyquid_initialize(category: u32) -> u32 {
    initialize_volatile_heap(category as u8);
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
    let allocator = &volatile_segment_header().allocator;
    unsafe { allocator.alloc(alloc::Layout::from_size_align(size as usize, align as usize).unwrap()) }
}

/// Deallocate volatile memory.
#[unsafe(no_mangle)]
fn __lyquid_volatile_dealloc(base: u32, size: u32, align: u32) {
    use alloc::GlobalAlloc;
    let allocator = &volatile_segment_header().allocator;
    unsafe {
        allocator.dealloc(
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
fn initialize_volatile_heap(category: u8) {
    // always initialize the allocator for volatile memory
    let volatile_header = volatile_segment_header();
    volatile_header.category = category;
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

/// Defines a host-side API in WASM environment. It generates a function that directs the flow
/// control to the Lyquor host and returns upon completion.
macro_rules! host_api {
    ($fn:ident($($param:ident: $type:ty),*) -> $rt:ty; $($rest:tt)*) => {
        pub fn $fn($($param:$type),*) -> Result<$rt, $crate::LyquidError> {
            use $crate::prelude::decode_object;

            let output_raw = {
                #[link(wasm_import_module = "lyquor_api")]
                unsafe extern "C" {
                    fn $fn(base: u32, len: u32) -> u64;
                }
                // encode input
                let raw = $crate::prelude::encode_by_fields!($($param: $type),*);
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
        console_output(output: ConsoleSink, s: String);
        universal_procedural_call(target: LyquidID, group: Option<String>, method: String, input: Vec<u8>, client_params: Option<Bytes>) -> Vec<u8>;
        inter_lyquid_call(target: LyquidID, method: String, input: Vec<u8>) -> Vec<u8>;
        submit_call(params: lyquor_primitives::CallParams, signed: bool) -> Vec<u8>;
        sign(msg: Bytes, cipher: Cipher) -> Bytes;
        verify(msg: Bytes, cipher: Cipher, sig: Bytes, pubkey: Bytes) -> bool;
        random_bytes(length: usize) -> Vec<u8>;
        http_request(request: http::Request, options: Option<http::RequestOptions>) -> http::Response;
        check_ed25519_pubkey(pubkey: [u8; 32], qx: U256, qy: U256) -> bool;
        get_ed25519_address(pubkey: [u8; 32]) -> Option<Address>;
        trigger(group: String, method: String, input: Vec<u8>, mode: lyquor_primitives::TriggerMode);
    );
}

/// Print to the console (standard output).
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        lyquor_api::console_output($crate::lyquor_primitives::ConsoleSink::StdOut, format!($($arg)*)).unwrap();
    };
}

/// Print a line to the console (standard output).
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {
        lyquor_api::console_output($crate::lyquor_primitives::ConsoleSink::StdOut, format!($($arg)*) + "\n").unwrap();
    };
}

/// Print to the console (error output).
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {
        lyquor_api::console_output($crate::lyquor_primitives::ConsoleSink::StdErr, format!($($arg)*)).unwrap();
    };
}

/// Print a line to the console (error output).
#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {
        lyquor_api::console_output($crate::lyquor_primitives::StdErr, format!($($arg)*) + "\n").unwrap();
    };
}

/// Log a custom event that has happened. (Similar to Solidity's `emit` event, or `log*`
/// instruction in EVM.) **Only usable by network functions.**
#[macro_export]
macro_rules! log {
    ($tag: ident, $v: expr) => {{
        lyquor_api::log($crate::lyquor_primitives::LyteLog::new_from_tagged_value(
            stringify!($tag),
            $v,
        ))?
    }};
}

/// Initiate a inter-lyquid call. **Only usable by network functions.**
/// FIXME: enforce this at compile time.
#[macro_export]
macro_rules! call {
    (($service: expr).$method :ident($($var:ident: $type:ty = $val: expr),*) -> ($($ovar:ident: $otype:ty),*)) => {
        lyquor_api::inter_lyquid_call(
            $service,
            stringify!($method).to_string().into(),
            Vec::from(&$crate::prelude::encode_by_fields!($($var: $type = $val),*)[..]),
        ).and_then(|r| $crate::prelude::decode_by_fields!(&r, $($ovar: $otype),*).ok_or(LyquidError::LyquorOutput))
    };
}

/// Submit a certified call to the sequencing backend. Returns the backend-specific
/// submission result as raw bytes (e.g., tx hash for EVM).
#[macro_export]
macro_rules! submit_certified_call {
    ($cert:expr) => {{
        // By default, rely on the node to sign.
        lyquor_api::submit_call($cert, false)
    }};
    ($cert:expr, $signed:expr) => {{ lyquor_api::submit_call($cert, $signed) }};
}

/// Trigger a timer function with a given mode, e.g interval.
#[macro_export]
macro_rules! trigger {
    (($($group:ident)::*) $method:ident($($param:ident: $type:ty $(= $default:expr)?),*), $mode:expr) => {
        $crate::runtime::lyquor_api::trigger(
            stringify!($($group)::*).to_string(),
            stringify!($method).to_string(),
            $crate::prelude::encode_by_fields!($($param: $type $(= $default)?),*),
            $mode,
        ).map_err(|e| $crate::LyquidError::LyquidRuntime(format!("Failed to trigger {} :{e:?}.", stringify!($method))))?
    };
    ($method:ident($($param:ident: $type:ty $(= $default:expr)?),*), $mode:expr) => {
        $crate::runtime::lyquor_api::trigger(
            $crate::lyquor_primitives::GROUP_DEFAULT.to_string(),
            stringify!($method).to_string(),
            $crate::prelude::encode_by_fields!($($param: $type $(= $default)?),*),
            $mode,
        ).map_err(|e| $crate::LyquidError::LyquidRuntime(format!("Failed to trigger {} :{e:?}.", stringify!($method).to_string())))?
    }
}

/// Initiate a Universal Procedure Call (UPC). **Only usable by instance functions.**
#[macro_export]
macro_rules! upc {
    (($network: expr).$method: ident($($var:ident: $type:ty = $val: expr),*) -> ($($ovar:ident: $otype:ty),*)) => {
        lyquor_api::universal_procedural_call(
            $network,
            None, // TODO: allow user to specify group with upc macro
            stringify!($method).to_string().into(),
            Vec::from(&$crate::prelude::encode_by_fields!($($var: $type = $val),*)[..]),
            None,
        ).and_then(|r| $crate::prelude::decode_by_fields!(&r, $($ovar: $otype),*).ok_or(LyquidError::LyquorOutput))
    };

    (($network: expr).$method: ident[$($params:ident: $params_type:ty = $params_val: expr),*]($($var:ident: $type:ty = $val: expr),*) -> ($($ovar:ident: $otype:ty),*)) => {
        lyquor_api::universal_procedural_call(
            $network,
            None, // TODO: allow user to specify group with upc macro
            stringify!($method).to_string().into(),
            Vec::from(&$crate::prelude::encode_by_fields!($($var: $type = $val),*)[..]),
            Some($crate::prelude::encode_by_fields!($($params: $params_type = $params_val),*).into()),
        ).and_then(|r| $crate::prelude::decode_by_fields!(&r, $($ovar: $otype),*).ok_or(LyquidError::LyquorOutput))
    };
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
    pub lyquid_id: LyquidID,
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
            lyquid_id: ctx.lyquid_id,
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
    pub lyquid_id: LyquidID,
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
            lyquid_id: ctx.lyquid_id,
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
    pub lyquid_id: LyquidID,
    pub node_id: NodeID,
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
            lyquid_id: ctx.lyquid_id,
            node_id: ctx.node_id.unwrap(), // If this panics then we have a bug as this is InstanceContext
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new()?),
            instance: Mutable::new(I::new()?),
        })
    }
}

/// Read-only wrapper for state variables.
pub struct ImmutableInstanceContextImpl<S, I>
where
    S: StateAccessor,
    I: StateAccessor,
{
    pub lyquid_id: LyquidID,
    pub node_id: NodeID,
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
            lyquid_id: ctx.lyquid_id,
            node_id: ctx.node_id.unwrap(), // If this panics then we have a bug as this is InstanceContext
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new()?),
            instance: Immutable::new(I::new()?),
        })
    }
}
