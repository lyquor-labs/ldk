/// Defines network-level and instance-level persistent state variables for a Lyquid contract.
///
/// ## Syntax: `lyquid::state!` Macro
///
/// The `lyquid::state!` macro is used to define state variables for your Lyquid. You should:
/// - **NEVER** mutably access any `static` variables in your Lyquid because only the variables defined
/// with this macro preserve their state from call to call. (This also applies to the third-party
/// libraries you include, so you should make sure they don't rely on the global state in any statics.)
/// - Invoke this macro **once** per Lyquid (your crate) in your **crate root** (i.e.,
/// `src/lib.rs`) to be correctly accessed by your Lyquid functions defined through [lyquid::method!](crate::method).
/// Using it multiple times will result in a **compilation error**, as it would lead to conflicting
/// `__lyquid` modules.
///
/// ### Macro Syntax
///
/// ```ignore
/// // in your src/lib.rs (crate root)
/// lyquid::state! {
///     <category> <variable_name>: <type> = <initializer>;
///     ...
/// }
/// // then there will be a `crate::__lyquid` defined that'd be used by your lyquid functions.
/// ```
///
/// ### `<category>`
///
/// - `network`: **global, consensus-driven state variable**, mutated by chain-level transactions.  
///   All nodes that host the same Lyquid observe the same `network` state version (tracked by [lyquor_primitives::LyquidNumber]).  
///   Network state is accessible via:
///   - **read/write** in `network` functions  
///   *(Conceptually similar to Solidity's contract-level storage variables)*
///   - **read-only** in `instance` functions  
///
/// - `instance`: **local, per-node state variable**, mutated by off-chain or external events (e.g., UPCs, timers, network events).  
///   Each node may hold a different value for the same `instance` variable. Instance state is accessible via:
///   - **read/write** in `instance` functions only
///
/// ### `<type>`
///
/// You may define network/instance variables using any primitive types or nested user-defined structs — **as long as they don't include heap references like `Box`, `Rc`, `Arc`, or raw pointers**.
///
/// If your type **does require heap allocation**, you must explicitly use the correct allocator:
///
/// - `network::Allocator` for network variables  
/// - `instance::Allocator` for instance variables
///
/// This also applies to **nested structures**. For example:
///
/// ```ignore
/// network::Vec<network::Vec<network::Vec<u64>>>
/// ```
///
/// All inner allocations must also use the correct allocator category.
///
/// ⚠ **Failure to do so may result in undefined memory access or state corruption.**
///
/// Most of the time, you won't run into this issue — the SDK provides re-exported standard containers like [network::Vec](super::network::Vec), [network::HashMap](super::network::HashMap), [instance::Vec](super::instance::Vec), etc., which handle this automatically.
///
/// If you're using **third-party data structures**, you must ensure they use the correct allocator throughout the object tree.  
/// *(Unfortunately, due to limitations in the Rust type system, this cannot be fully automated.)*
///
/// ---
///
/// ### Generated Contexts and Access Patterns
///
/// When using `lyquid::state!`, a module `__lyquid` is generated with the following types:
///
/// #### `__lyquid::NetworkContext` (used in `network` functions):
///
/// - `origin: Address` – origin of the call  (like `tx.origin` in Solidity)
/// - `caller: Address` – direct caller (like `msg.sender` in Solidity)
/// - `input: Bytes` – raw input buffer (decoded values already available via parameters)  
/// - `self_address: Address` – the Ethereum contract address (not Lyquid ID) of this contract
/// - `network: lyquid::runtime::Mutable<NetworkState>` – access to your `network` state variables
///
/// #### `__lyquid::InstanceContext` (used in `instance` functions):
///
/// - `origin: Address` - this will always be the same as `caller`
/// - `caller: Address` - external caller
/// - `input: Bytes`  
/// - `self_address: Address` – the Ethereum contract address (not Lyquid ID) of this contract
/// - `network: lyquid::runtime::Immutable<NetworkState>` – **read-only view of network state**  
/// - `instance: lyquid::runtime::Mutable<InstanceState>` – access to `instance` state variables
///
/// #### `lyquid::runtime::Mutable` and `lyquid::runtime::Immutable`
///
/// Internal wrappers that enforce correct mutability constraints in a given execution context.  
/// Invalid writes (e.g., writing `network` state from an `instance` function) are silently discarded and do not persist.
///
/// ---
///
/// ### Example
///
/// ```ignore
/// struct MyData {
///     // A byte vector for network state — must use network::Vec
///     arr: network::Vec<u8>,
///     x: u64,
///     y: u64,
/// }
///
/// struct MyNestedData {
///     // Nested container must also use the correct allocator
///     entries: network::Vec<MyData>,
/// }
///
/// lyquid::state! {
///     // A simple global counter
///     network my_previous_int: u64 = 0;
///
///     // A complex network-level structure
///     network complex_data: MyNestedData;
///
///     // A local instance-level variable (different per node)
///     instance local_counter: u64 = 0;
/// }
/// ```
#[macro_export]
macro_rules! state {
    {$($cat:ident $var:ident: $type:ty = $init:expr;)*} => {
        pub mod __lyquid {
            use super::*;
            use $crate::runtime::*;

            internal::setup_lyquid_state_variables!(
                State
                __lyquid_initialize_state_variables
                [(network NetworkAlloc Network StateCategory::Network)
                (instance InstanceAlloc Instance StateCategory::Instance)] $(($cat $var $type $init))*);

            pub type NetworkContext = $crate::runtime::NetworkContextImpl<NetworkState>;
            pub type ImmutableNetworkContext = $crate::runtime::ImmutableNetworkContextImpl<NetworkState>;
            pub type InstanceContext = $crate::runtime::InstanceContextImpl<NetworkState, InstanceState>;
            pub type ImmutableInstanceContext = $crate::runtime::ImmutableInstanceContextImpl<NetworkState, InstanceState>;
            pub type UpcCalleeContext = $crate::runtime::upc::CalleeContextImpl<NetworkState>;
            pub type UpcRequestContext = $crate::runtime::upc::RequestContextImpl<NetworkState, InstanceState>;
            pub type UpcResponseContext = $crate::runtime::upc::ResponseContextImpl<NetworkState>;
        }
    }
}

/// Defines network, instance, and UPC methods (functions) for a Lyquid contract.
///
/// ## Syntax: `lyquid::method!` Macro
///
/// The `lyquid::method!` macro defines functions within a Lyquid contract.
/// These methods may execute with network or instance context, and can also include UPC procedures.
/// All Lyquid functions should be described with this macro. Unlike [state] macro, you can use it
/// multiple times as convenient through out your Lyquid crate (in any file, so it's like
/// "exporting" the public functions for the Lyquid that could be invoked through the platform).
///
/// All functions defined with this macro are in the same global namespace, which means there is one function allowed given the same `<category>`, `<group>` and `<method_name>`.
///
///
/// ### Constructor (optional):
/// The constructor of the Lyquid is guaranteed to be invoked atomically (and only once) when the
/// Lyquid is deployed (or a new Lyquid code updates the old code).
///
/// ```ignore
/// lyquid::method! {
///     constructor(&mut <context>, <parameter_list>) {
///         // Constructor body
///     }
/// }
/// ```
///
/// ### Standard Method Definitions:
///
/// #### Abbreviated Form (defaults to `"main"` group):
/// ```ignore
/// lyquid::method! {
///     <category> fn <method_name>(&mut <context>, <parameter_list>) -> LyquidResult<ReturnType> {
///         // Function body
///     }
/// }
/// ```
///
/// #### Full Form (explicit group name):
///
/// ```ignore
/// lyquid::method! {
///     <category>(<group>) fn <method_name>(&mut <context>, <parameter_list>) -> LyquidResult<ReturnType> {
///         // Function body
///     }
/// }
/// ```
///
/// ### UPC Definitions
///
///
/// These expand the UPC lifecycle into three separate instance functions using dedicated groups.
///
/// #### 1. **UPC Callee Selection**
///
/// ```ignore
/// upc(callee) fn <method_name>(&<context>) -> LyquidResult<Vec<NodeID>> {
///     // Returns a list of NodeIDs representing the nodes to be invoked in this UPC instance.
/// }
/// ```
///
/// #### 2. **UPC Request Handler**
///
/// ```ignore
/// upc(request) fn <method_name>(&mut <context>, <UPC_parameter_list>) -> LyquidResult<ReturnType> {
///     // Executed by each callee node to perform the UPC-requested computation.
///
///     // Parameters:
///     // - `<context>.id`: Request ID (u64)
///     // - `<context>.from`: Caller's NodeID
/// }
/// ```
///
/// #### 3. **UPC Aggregator (Response Handler)**
///
/// ```ignore
/// upc(response) fn <method_name>(&<context>, response: LyquidResult<ReturnType>) -> LyquidResult<ReturnType> {
///     // Logic executed by the caller node to aggregate responses.
///
///     // Notes:
///     // - A temporary, volatile UPC-local context is available for aggregation purposes.
///     // - This context is discarded once the UPC call completes or errors.
/// }
/// ```
///
/// ### Notes on `<category>` and `<context>`
///
/// #### `<category>`:
///
/// - `network`:
///   A **consensus (sequencer) event-driven function** executed deterministically by all nodes hosting the same Lyquid.  
///   It operates on **network state**, which is shared and versioned across all nodes.
///
///   network functions can **read and write `network` state**, and their execution is included in the contract's consensus logic. UPC, and other builtins that involve interaction with nondeterminism are not available in network functions.
///
/// - `instance`:
///   An **external event-driven function**, typically triggered by nondeterministic events such as **UPC calls**, **network messages**, or **timers**.  
///   These functions operate on **instance-local state**, which is specific to each node instance.
///
///   Instance functions can **read/write `instance` state**, and **read `network` state**, but they **can not mutate shared `network` state** — to avoid nondeterminism. They can also initiate a UPC call and invoke other bultins that involve nondeterminism.
///
/// #### `<context>`:
///
/// The `context` identifier (commonly `ctx`, but you can use your own choice such as `self`)
/// provides access to runtime state within the function.
///
/// - For `network` functions: the context is typed as `__lyquid::NetworkContext`  
/// - For `instance` functions: the context is typed as `__lyquid::InstanceContext`
///
/// Typical access patterns:
/// ```ignore
/// ctx.network.my_network_state_var
/// ctx.instance.my_instance_state_var
/// ```
///
/// See [state] for more information on how network and instance states are defined and accessed.
///
/// #### Special Notes on UPC Functions:
///
/// - The `upc_callee` function (which defines dynamic callee selection logic) is **optional**.  
///   If omitted, the caller must manually specify which nodes should participate in the UPC call.
///
/// - The `upc_response` aggregator function is also **optional**.  
///   If omitted, UPC behaves like a traditional **RPC-style request-response**, where the result from one node is taken as the final result.
///
#[macro_export]
macro_rules! method {
    {$($rest:tt)*} => {
        const _: () = {
            $crate::__lyquid_categorize_methods!({$($rest)*}, {}, {});
        };
    }
}

/// Categorize user-defined functions by their category keywords and transform them into Lyquid
/// functions.
#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_categorize_methods {
    ({network($group:ident) fn $fn:ident(&mut $handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*}, // recurisvely categorize the rest of the funcs
            {$($network_funcs)* // append this func to the end of network_funcs
                $group (true) fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::NetworkContext::new(ctx)?;
                    let result = $body; // execute the body of the function
                    drop($handle); // drop the state handle here to ensure the correct lifetime
                                   // for the handle when accessed in $body so the handle is not
                                   // leaked out by the result
                    result
                }}
            },
            {$($instance_funcs)*} // retain the collected instance_funcs
        );
    };

    ({network($group:ident) fn $fn:ident(&$handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*}, // recurisvely categorize the rest of the funcs
            {$($network_funcs)* // append this func to the end of network_funcs
                $group (false) fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let $handle = __lyquid::ImmutableNetworkContext::new(ctx)?;
                    let result = $body; // execute the body of the function
                    drop($handle); // drop the state handle here to ensure the correct lifetime
                                   // for the handle when accessed in $body so the handle is not
                                   // leaked out by the result
                    result
                }}
            },
            {$($instance_funcs)*} // retain the collected instance_funcs
        );
   };

    // Network function syntax sugar
    ({network fn $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({network(main) fn $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };

    ({network($group:ident) fn $fn:ident(&mut $handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({network($group) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };

    ({network($group:ident) fn $fn:ident(&$handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({network($group) fn $fn(&$handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };

    ({constructor($($args:tt)*) $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({
        network(main) fn __lyquid_constructor($($args)*) -> LyquidResult<bool> {$body; Ok(true)} $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };

    ({upc(callee) fn $fn:ident(&$handle:ident) -> LyquidResult<Vec<NodeID>> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                // see CalleeInput
                upc_callee (true) fn $fn(id: u64) -> LyquidResult<$crate::upc::CalleeOutput> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::UpcCalleeContext::new(ctx, id)?;
                    let result: LyquidResult<Vec<NodeID>> = $body;
                    drop($handle);
                    result.map(|r| $crate::upc::CalleeOutput { result: r })
                }}
            }
        );
    };

    ({upc(request) fn $fn:ident(&mut $handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                // see RequestInput
                upc_request (true) fn $fn(from: $crate::NodeID, id: u64, input: Vec<u8>) -> LyquidResult<$rt> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::UpcRequestContext::new(ctx, from, id)?;
                    let input = $crate::lyquor_primitives::decode_by_fields!(&input, $($name: $type),*).ok_or($crate::LyquidError::LyquorInput)?;
                    $(let $name = input.$name;)*
                    let result = $body;
                    drop($handle);
                    result
                }}
            }
        );
    };
    ({upc(request) fn $fn:ident(&mut $handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({upc(request) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };

    // TODO: handle immutable UPC request correctly
    ({upc(request) fn $fn:ident(&$handle:ident, $($name:ident: $type:ty),*) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({upc(request) fn $fn(&mut $handle, $($name: $type),*) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };
    ({upc(request) fn $fn:ident(&$handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({upc(request) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };

    ({upc(response) fn $fn:ident(&$handle:ident, $returned:ident: LyquidResult<$rt:ty>) -> LyquidResult<Option<$rt_:ty>> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                // see ResponseInput
                upc_response (true) fn $fn(from: $crate::NodeID, id: u64, returned: Vec<u8>, cache: Option<Vec<u8>>) -> LyquidResult<$crate::upc::ResponseOutput> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::UpcResponseContext::new(ctx, from, id, cache)?;
                    let $returned = $crate::lyquor_primitives::decode_object::<LyquidResult<$rt>>(&returned).ok_or($crate::LyquidError::LyquorInput)?;
                    let result: LyquidResult<Option<$rt_>> = $body;
                    let cache = $handle.cache.take_cache();
                    drop($handle);
                    result.map(|r|
                        match r {
                            // turn the inner returned user-supplied object into serialized form so the caller can pass it on without knowing the type
                            Some(r) => $crate::upc::ResponseOutput::Return(Vec::from(&$crate::lyquor_primitives::encode_object(&r)[..])),
                            // turn te cache into raw pointer so it won't be dropped
                            None => $crate::upc::ResponseOutput::Continue(cache.map(|c| (Box::into_raw(c) as usize).to_be_bytes().to_vec())),
                        })
                }}
            }
        );
    };

    ({instance($group:ident) fn $fn:ident(&mut $handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                $group (true) fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::InstanceContext::new(ctx)?;
                    let result = $body;
                    drop($handle);
                    result
                }}
            }
        );
    };
    ({instance($group:ident) fn $fn:ident(&$handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                $group (false) fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let $handle = __lyquid::ImmutableInstanceContext::new(ctx)?;
                    let result = $body;
                    drop($handle);
                    result
                }}
            }
        );
    };
    ({instance($group:ident) fn $fn:ident(&mut $handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance(main) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };
    ({instance($group:ident) fn $fn:ident(&$handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance(main) fn $fn(&$handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };

    // instance function syntax sugar
    ({instance fn $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance(main) fn $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}); };

    ({}, {$($network_funcs:tt)*}, {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_wrap_methods!("__lyquid_method_network", $($network_funcs)*);
        $crate::__lyquid_wrap_methods!("__lyquid_method_instance", $($instance_funcs)*);
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_method_alias {
    ("__lyquid_method_network" $group:ident (false) $fn:ident) => {
        #[prefix_item("__lyquid_method_instance", "info", $group)]
        #[unsafe(no_mangle)]
        fn $fn(base: u32, len: u32, abi: u32) -> u64 {
            prefix_call!(("__lyquid_method_network", "info", $group), $fn(base, len, abi))
        }

        #[prefix_item("__lyquid_method_instance", $group)]
        #[unsafe(no_mangle)]
        fn $fn(base: u32, len: u32, abi: u32) -> u64 {
            prefix_call!(("__lyquid_method_network", $group), $fn(base, len, abi))
        }
    };
    ("__lyquid_method_network" $group:ident (true) $fn:ident) => {};
    ("__lyquid_method_instance" $group:ident (false) $fn:ident) => {};
    ("__lyquid_method_instance" $group:ident (true) $fn:ident) => {};
}

/// Transform a user-defined WASM function into a Lyquid function that can be invoked by the host.
#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_wrap_methods {
    ($prefix:tt, $group:ident ($mutable:ident) fn $fn:ident($($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*) => {
        #[$crate::runtime::internal::prefix_item($prefix, $group)]
        mod $fn {
            use super::*;
            use $crate::alloy_dyn_abi::{DynSolType, DynSolValue};
            use $crate::runtime::*;
            use $crate::runtime::internal::*;
            use $crate::lyquor_primitives::{encode_object, decode_object, decode_by_fields};

            #[inline(always)]
            fn gen_type_string(form: u8) -> Option<String> {
                // assemble eth abi string for each parameter
                gen_eth_type_string::<$rt>(form,
                    [$((<$type as EthABI>::type_string(), <$type as EthABI>::is_scalar())),*].into_iter())
            }

            #[prefix_item($prefix, "info", $group)]
            #[unsafe(no_mangle)]
            fn $fn(base: u32, len: u32, _: u32) -> u64 {
                let raw = unsafe { HostInput::new(base, len) };
                let flag: Option<u8> = decode_object(&raw);
                drop(raw);
                output_to_host(&encode_object(&flag.and_then(|f| {
                    // declaration form (with "memory", "calldata", etc)
                    let eth_decl = gen_type_string(0x1 + f);
                    // canonical form (good for selector calculation after stripping off whitespaces)
                    let eth_canonical = gen_type_string(0x0);
                    Some(FuncInfo {
                        eth: eth_decl.and_then(|decl|
                                               eth_canonical.map(|canonical| FuncEthInfo {decl, canonical})),
                        mutable: $mutable,
                    })
                })))
            }

            #[prefix_item($prefix, $group)]
            #[unsafe(no_mangle)]
            fn $fn(base: u32, len: u32, abi: u32) -> u64 {
                let raw = unsafe { HostInput::new(base, len) };
                let output = if abi == ABI_ETH {
                    let result = (|| -> Result<$rt, LyquidError> {
                        let (input, ctx) = (|| {
                            <$rt as EthABI>::type_string()?;
                            let ctx: $crate::CallContext = decode_object(&raw)?;

                            // We cache the Solidity type decoder so Eth ABI string will only be generated once
                            static SOL_TYPE_CACHED: std::sync::OnceLock<Option<DynSolType>> = std::sync::OnceLock::new();
                            let sol_type = SOL_TYPE_CACHED.get_or_init(|| {
                                gen_type_string(0).and_then(|s| DynSolType::parse(&s).ok())
                            }).as_ref()?;

                            // decode to a list of DynSolValue
                            let mut iter = match sol_type.abi_decode_params(&ctx.input).ok()? {
                                DynSolValue::Tuple(v) => v.into_iter(),
                                _ => return None,
                            };
                            struct Parameters {$($name: $type),*}
                            // then let each type use its trait method to decode further
                            Some((Parameters {
                                $($name: <$type as EthABI>::decode(iter.next()?)?),*
                            }, ctx))
                        })().ok_or(LyquidError::LyquorInput)?;
                        drop(raw);
                        // set up the context so the function developer feels as if these parameters in
                        // the input are real
                        $(let $name = input.$name;)*
                        // execute the function body
                        ($body)(ctx)
                    })().map(|rt| rt.encode().abi_encode());
                    encode_object(&result)
                } else {
                    let result = (|| -> Result<$rt, LyquidError> {
                        let (input, ctx) = (|| {
                            let ctx: $crate::CallContext = decode_object(&raw)?;
                            Some((decode_by_fields!(&ctx.input, $($name: $type),*)?, ctx))
                        })().ok_or(LyquidError::LyquorInput)?;
                        drop(raw);
                        // set up the context so the function developer feels as if these parameters in
                        // the input are real
                        $(let $name = input.$name;)*
                        // execute the function body
                        ($body)(ctx)
                    })();
                    encode_object(&result)
                };
                // TODO: possible improvement to not copy this already WASM-allocated vector? But
                // need to make sure it can be properly deallocated.
                output_to_host(&output)
            }

            $crate::__lyquid_method_alias!($prefix $group ($mutable) $fn);
        }

        $crate::__lyquid_wrap_methods!($prefix, $($rest)*);
    };
    ($prefix:tt,) => {}
}
