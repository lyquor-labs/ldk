#![doc(html_no_source)] // remove it upon open-source
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
    self, LyquidID, LyquidNumber, LyteLog, NodeID, StateCategory, U64, U128, U256, address, blake3, uint,
};
pub use lyquor_primitives::{Address, Bytes, ConsoleSink, anyhow};

#[cfg(feature = "ldk")] pub mod runtime;

#[cfg_attr(feature = "ldk", doc(hidden))]
#[derive(Serialize, Deserialize, Clone)]
pub struct CallContext {
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
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
}

pub const GROUP_DEFAULT: &str = "main";
pub const GROUP_NODE: &str = "node";
pub const GROUP_UPC_CALLEE: &str = "upc_callee";
pub const GROUP_UPC_REQ: &str = "upc_request";
pub const GROUP_UPC_RESP: &str = "upc_response";

pub const ABI_ETH: u32 = 0x1;
pub const ABI_LYQUOR: u32 = 0x0;

pub type LyquidResult<T> = Result<T, LyquidError>;

/// The starting address for stacks used by Lyquid.
pub const LYTESTACK_BASE: usize = 0x30000000;
/// The base address for LyteMemory.
/// Volatile's upper address is below next to this address. Everything from this base to
/// [SERVICE_MEMSIZE_IN_MB] and [INSTANCE_MEMSIZE_IN_MB] are persistent.
pub const LYTEMEM_BASE: usize = 0x80000000;
/// Total size of the memory in megabytes.
pub const LYTEMEM_SIZE_IN_MB: usize = 4096; // 4GB (WASM limit)
/// Size cap for the addressable LyteMemory that is globally viewed (and persisted) by all Lyquid instances.
pub const SERVICE_MEMSIZE_IN_MB: usize = 1024; // 1GB
/// Size cap for the addressable LyteMemory that is locally viewed (and persisted) for one Lyquid instance.
pub const INSTANCE_MEMSIZE_IN_MB: usize = 1024; // 1GB
/// Size cap for the volatile memory that can be used by each function call.
pub const VOLATILE_MEMSIZE_IN_MB: usize = 1024; // 1GB

/// Prefix bytes used for varaiable catalog in versioned state.
pub const VAR_CATALOG_PREFIX: [u8; 1] = [0x2a];
/// Prefix bytes used for lite pages in versioned state.
pub const LYTEMEM_PAGE_PREFIX: [u8; 1] = [0x00];

pub const WASM_INIT_FUNC: &str = "__lyquid_initialize";
pub const WASM_INIT_VAR_FUNC: &str = "__lyquid_initialize_state_variables";
pub const WASM_NUKE_STATE_FUNC: &str = "__lyquid_nuke_state";

pub const WASM_VOLATILE_ALLOC_FUNC: &str = "__lyquid_volatile_alloc";
pub const WASM_VOLATILE_DEALLOC_FUNC: &str = "__lyquid_volatile_dealloc";
pub const WASM_STACK_POINTER: &str = "__stack_pointer";
pub const WASM_SERVICE_METHOD_PREFIX: &str = "__lyquid_method_service";
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

    pub type RequestOutput = Vec<u8>;

    #[derive(Serialize, Deserialize)]
    pub struct ResponseInput {
        pub from: NodeID,
        pub id: u64,
        pub returned: Vec<u8>,
    }

    pub type ResponseOutput = Option<Vec<u8>>;

    #[derive(Serialize, Deserialize)]
    pub struct CalleeInput {
        //pub from: lyquor_primitives::NodeID,
        pub id: u64,
    }

    pub type CalleeOutput = Vec<NodeID>;
}
