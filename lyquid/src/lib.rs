#![cfg_attr(feature = "ldk", feature(allocator_api, btreemap_alloc))]
#![cfg_attr(feature = "ldk", allow(incomplete_features))] // used by specialization feature
#![cfg_attr(feature = "ldk", feature(specialization))] // only used by EthABI

//! - [Litepaper](https://docs.lyquor.dev/docs/litepaper/arch)
//! - [Tutorial](https://docs.lyquor.dev/docs/tutorial/)
//! - [Lyquor Development Kit Documentation](https://docs.lyquor.dev/docs/ldk/)

pub use alloy_dyn_abi;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

#[cfg(feature = "ldk")]
pub use lyquor_primitives::{
    self, Hash, LyquidID, LyquidNumber, LyteLog, NodeID, RequiredLyquid, StateCategory, U64, U128, U256, address,
    blake3, decode_by_fields, encode_by_fields, uint,
};

pub type CallParams = lyquor_primitives::CallParams<Bytes>;

pub use lyquor_primitives::{
    Address, Bytes, ConsoleSink, GROUP_DEFAULT, GROUP_NODE, GROUP_UPC_CALLEE, GROUP_UPC_REQ, GROUP_UPC_RESP, OracleCert,
};

use lyquor_primitives::arc_option_serde;

#[cfg(feature = "ldk")] pub mod runtime;

#[cfg_attr(feature = "ldk", doc(hidden))]
#[derive(Serialize, Deserialize, Clone)]
pub struct CallContext {
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    #[serde(with = "arc_option_serde", default)]
    pub input_cert: Option<Arc<OracleCert>>,
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
    pub struct CalleeInput {
        //pub from: lyquor_primitives::NodeID,
        pub id: u64,
    }

    #[derive(Serialize, Deserialize)]
    pub struct CalleeOutput {
        pub result: Vec<NodeID>,
    }
}
