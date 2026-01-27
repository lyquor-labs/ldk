#![cfg_attr(feature = "ldk", feature(allocator_api, btreemap_alloc))]
#![cfg_attr(feature = "ldk", allow(incomplete_features))] // used by specialization feature
#![cfg_attr(feature = "ldk", feature(specialization))] // only used by EthABI

//! - [Litepaper](https://docs.lyquor.dev/docs/litepaper/arch)
//! - [Tutorial](https://docs.lyquor.dev/docs/tutorial/)
//! - [Lyquor Development Kit Documentation](https://docs.lyquor.dev/docs/ldk/)

pub use alloy_dyn_abi;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "ldk")]
pub use lyquor_primitives::{
    self, LyquidNumber, LyteLog, RequiredLyquid, StateCategory, U64, U128, U256, address, blake3, decode_by_fields,
    encode_by_fields, uint,
};

pub use lyquor_primitives::{
    Address, Bytes, CallParams, ConsoleSink, GROUP_DEFAULT, GROUP_NODE, GROUP_UPC_PREPARE, GROUP_UPC_REQ,
    GROUP_UPC_RESP, Hash, LyquidID, NodeID,
};

pub mod http;
#[cfg(feature = "ldk")] pub mod runtime;

#[cfg(feature = "ldk")]
/// Lyquid method syntax (attribute macros).
///
/// Lyquid functions are defined with attribute macros. These methods may execute with network or
/// instance context, and can include UPC procedures. Define them as top-level functions in your
/// crate (module-level items, not inside `impl`/`trait` blocks). All functions are exported into a
/// single global namespace keyed by `<category>`, `<group>`, and `<method_name>`.
///
/// ### Constructor (optional)
/// The constructor is invoked atomically once at deployment (or code upgrade). It must be named
/// `constructor`, must not return a value, and must use `#[lyquid::method::network]` with no
/// attribute arguments.
///
/// ```ignore
/// #[lyquid::method::network]
/// fn constructor(ctx: &mut _, greeting: String) {
///     *ctx.network.greeting = greeting.into();
/// }
/// ```
///
/// ### Standard Methods
///
/// #### Network method (defaults to `main` group)
/// ```ignore
/// #[lyquid::method::network]
/// fn set_greeting(ctx: &mut _, greeting: String) -> LyquidResult<bool> {
///     *ctx.network.greeting = greeting.into();
///     Ok(true)
/// }
/// ```
///
/// #### Network method with explicit group
/// ```ignore
/// #[lyquid::method::network(group = "node")]
/// fn join(ctx: &mut _, node: NodeID) -> LyquidResult<()> {
///     ctx.network.nodes.push(node);
///     Ok(())
/// }
/// ```
///
/// #### Instance method
/// ```ignore
/// #[lyquid::method::instance]
/// fn get_price(ctx: &_) -> LyquidResult<U256> {
///     Ok(*ctx.instance.price.read())
/// }
/// ```
///
/// ### UPC Methods
///
/// UPC expands into three instance functions using dedicated groups.
///
/// #### 1. UPC callee selection
/// ```ignore
/// #[lyquid::method::instance(upc(prepare))]
/// fn ping(ctx: &_) -> LyquidResult<Vec<NodeID>> {
///     Ok(Vec::from(&ctx.network.nodes[..]))
/// }
/// ```
///
/// #### 2. UPC request handler
/// ```ignore
/// #[lyquid::method::instance(upc(request))]
/// fn ping(ctx: &mut _, msg: String) -> LyquidResult<String> {
///     let from = ctx.from;
///     let id = ctx.id;
///     Ok(format!("pong: {msg} ({from:?}, {id})"))
/// }
/// ```
///
/// #### 3. UPC response aggregator
/// ```ignore
/// #[lyquid::method::instance(upc(response))]
/// fn ping(ctx: &_, response: LyquidResult<String>) -> LyquidResult<Option<String>> {
///     let resp = response?;
///     let from = ctx.from;
///     Ok(Some(format!("from {from:?}: {resp}")))
/// }
/// ```
///
/// ### Notes on Categories and Context
/// - `network` methods are deterministic and can read/write `network` state. They cannot perform
///   nondeterministic operations (UPC, timers, etc.).
/// - `instance` methods are event-driven and can read/write `instance` state and read `network`
///   state, but cannot mutate shared `network` state.
/// - The context parameter must be a reference like `ctx: &mut _` or `ctx: &_`. The concrete
///   context type depends on the method category (network/instance/UPC).
/// - UPC `response` functions are optional. If omitted, UPC behaves like a request-response call
///   that returns the first result.
pub mod method {
    pub use lyquid_proc::instance_function as instance;
    pub use lyquid_proc::network_function as network;
}

#[cfg_attr(feature = "ldk", doc(hidden))]
#[derive(Serialize, Deserialize, Clone)]
pub struct CallContext {
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub lyquid_id: LyquidID,
    pub node_id: Option<NodeID>,
}

#[derive(Serialize, Deserialize, Debug, Error)]
pub enum LyquidError {
    #[error("Fail to initialize Lyquid.")]
    Init,
    #[error("Invalid input given from the host.")]
    LyquorInput,
    #[error("Invalid output returned by the host call.")]
    LyquorOutput,
    #[error("Invalid input given from the Lyquid.")]
    LyquidInput,
    #[error("Invalid output returned by the Lyquid.")]
    LyquidOutput,
    #[error("Host runtime: {0}")]
    LyquorRuntime(String),
    #[error("Lyquid runtime: {0}")]
    LyquidRuntime(String),
    #[error("Invalid certificate for the input.")]
    InputCert,
    #[error("Oracle error: {0}")]
    OracleError(String),
}

pub const ABI_ETH: u32 = 0x1;
pub const ABI_LYQUOR: u32 = 0x0;

pub type LyquidResult<T> = Result<T, LyquidError>;

/// The starting address for stacks used by Lyquid.
pub const LYTESTACK_BASE: usize = 0x30000000;
/// The base address for LyteMemory.
/// Volatile's upper address is below next to this address. Everything from this base to
/// [NETWORK_MEMSIZE_IN_MB] and [INSTANCE_MEMSIZE_IN_MB] are persistent.
pub const LYTEMEM_BASE: usize = 0x80000000;
/// Total size of the memory in megabytes.
pub const LYTEMEM_SIZE_IN_MB: usize = 4096; // 4GB (WASM limit)
/// Size cap for the addressable LyteMemory that is globally viewed (and persisted) by all Lyquid instances.
pub const NETWORK_MEMSIZE_IN_MB: usize = 1024; // 1GB
/// Size cap for the addressable LyteMemory that is locally viewed (and persisted) for one Lyquid instance.
pub const INSTANCE_MEMSIZE_IN_MB: usize = 1024; // 1GB
/// Size cap for the volatile memory that can be used by each function call.
pub const VOLATILE_MEMSIZE_IN_MB: usize = 1024; // 1GB

/// Prefix bytes used for varaiable catalog in versioned state.
pub const VAR_CATALOG_PREFIX: [u8; 1] = [0x2a];
pub const INTERNAL_STATE_PREFIX: [u8; 1] = [0x20];
/// Prefix bytes used for lite pages in versioned state.
pub const LYTEMEM_PAGE_PREFIX: [u8; 1] = [0x00];

pub const WASM_INIT_FUNC: &str = "__lyquid_initialize";
pub const WASM_INIT_VAR_FUNC: &str = "__lyquid_initialize_state_variables";
pub const WASM_NUKE_STATE_FUNC: &str = "__lyquid_nuke_state";

pub const WASM_VOLATILE_ALLOC_FUNC: &str = "__lyquid_volatile_alloc";
pub const WASM_VOLATILE_DEALLOC_FUNC: &str = "__lyquid_volatile_dealloc";
pub const WASM_STACK_POINTER: &str = "__stack_pointer";
pub const WASM_NETWORK_METHOD_PREFIX: &str = "__lyquid_method_network";
pub const WASM_INSTANCE_METHOD_PREFIX: &str = "__lyquid_method_instance";
/// The maximum size of a stack per call.
pub const WASM_CALLSTACK_LIMIT: u32 = 0x100000; // 1M
pub const WASM_DEFAULT_STACK_BASE: u32 = 0x100000;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuncEthInfo {
    pub decl: String,
    pub canonical: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FuncInfo {
    pub eth: Option<FuncEthInfo>,
    pub mutable: bool, // &mut ctx or &ctx
}

pub mod upc {
    use super::*;
    use lyquor_primitives::NodeID;

    #[derive(Serialize, Deserialize)]
    pub struct RequestInput {
        pub from: NodeID,
        pub id: u64,
        pub input: Vec<u8>,
    }

    // TODO: refactor request output to be a struct with more sophisticated error handling
    pub type RequestOutput = Vec<u8>;

    pub type CachePtr = u64;

    #[derive(Serialize, Deserialize)]
    pub struct ResponseInput {
        pub from: NodeID,
        pub id: u64,
        pub returned: Vec<u8>,
        pub cache: Option<CachePtr>,
    }

    /// The ResponseOutput is similar to std::ops::ControlFlow, we don't depend on std::ops::ControlFlow because it is
    /// not serializable.
    #[derive(Serialize, Deserialize)]
    pub enum ResponseOutput {
        Continue(Option<CachePtr>),
        Return(Vec<u8>),
    }

    #[derive(Serialize, Deserialize)]
    pub struct PrepareInput {
        pub client_params: Bytes,
    }

    #[derive(Serialize, Deserialize)]
    pub struct PrepareOutput {
        pub result: Vec<NodeID>,
        pub cache: Option<CachePtr>,
    }
}
