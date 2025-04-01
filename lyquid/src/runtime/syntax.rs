/// Defines service-level and instance-level persistent state variables for a Lyquid contract.
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
/// - `service`: **global, consensus-driven state variable**, mutated by chain-level transactions.  
///   All nodes that host the same Lyquid observe the same `service` state version (tracked by [lyquor_primitives::LyquidNumber]).  
///   Service state is accessible via:
///   - **read/write** in `service` functions  
///   *(Conceptually similar to Solidity's contract-level storage variables)*
///   - **read-only** in `instance` functions  
///
/// - `instance`: **local, per-node state variable**, mutated by off-chain or external events (e.g., UPCs, timers, network events).  
///   Each node may hold a different value for the same `instance` variable. Instance state is accessible via:
///   - **read/write** in `instance` functions only
///
/// ### `<type>`
///
/// You may define service/instance variables using any primitive types or nested user-defined structs — **as long as they don't include heap references like `Box`, `Rc`, `Arc`, or raw pointers**.
///
/// If your type **does require heap allocation**, you must explicitly use the correct allocator:
///
/// - `service::Allocator` for service variables  
/// - `instance::Allocator` for instance variables
///
/// This also applies to **nested structures**. For example:
///
/// ```ignore
/// service::Vec<service::Vec<service::Vec<u64>>>
/// ```
///
/// All inner allocations must also use the correct allocator category.
///
/// ⚠ **Failure to do so may result in undefined memory access or state corruption.**
///
/// Most of the time, you won't run into this issue — the SDK provides re-exported standard containers like [service::Vec](super::service::Vec), [service::HashMap](super::service::HashMap), [instance::Vec](super::instance::Vec), etc., which handle this automatically.
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
/// #### `__lyquid::ServiceContext` (used in `service` functions):
///
/// - `origin: Address` – origin of the call  (like `tx.origin` in Solidity)
/// - `caller: Address` – direct caller (like `msg.sender` in Solidity)
/// - `input: Bytes` – raw input buffer (decoded values already available via parameters)  
/// - `service: __lyquid::Mutable<ServiceState>` – access to your `service` state variables
///
/// #### `__lyquid::InstanceContext` (used in `instance` functions):
///
/// - `origin: Address` - this will always be the same as `caller`
/// - `caller: Address` - external caller
/// - `input: Bytes`  
/// - `service: __lyquid::Immutable<ServiceState>` – **read-only view of service state**  
/// - `instance: __lyquid::Mutable<InstanceState>` – access to `instance` state variables
///
/// #### `__lyquid::Mutable` and `__lyquid::Immutable`
///
/// Internal wrappers that enforce correct mutability constraints in a given execution context.  
/// Invalid writes (e.g., writing `service` state from an `instance` function) are silently discarded and do not persist.
///
/// ---
///
/// ### Example
///
/// ```ignore
/// struct MyData {
///     // A byte vector for service state — must use service::Vec
///     arr: service::Vec<u8>,
///     x: u64,
///     y: u64,
/// }
///
/// struct MyNestedData {
///     // Nested container must also use the correct allocator
///     entries: service::Vec<MyData>,
/// }
///
/// lyquid::state! {
///     // A simple global counter
///     service my_previous_int: u64 = 0;
///
///     // A complex service-level structure
///     service complex_data: MyNestedData;
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
                [(service ServiceAlloc Service StateCategory::Service)
                (instance InstanceAlloc Instance StateCategory::Instance)] $(($cat $var $type $init))*);

            pub struct Immutable<T>(T);

            impl<T> Immutable<T> {
                pub fn new(inner: T) -> Self { Self(inner) }
            }

            impl<T> std::ops::Deref for Immutable<T> {
                type Target = T;
                fn deref(&self) -> &T {
                    &self.0
                }
            }

            pub struct Mutable<T>(T);

            impl<T> Mutable<T> {
                pub fn new(inner: T) -> Self { Self(inner) }
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

            /// Read/write the service state variables, which is allowed for service funcs.
            pub struct ServiceContext {
                pub origin: Address,
                pub caller: Address,
                pub input: Bytes,
                pub service: Mutable<ServiceState>,
            }

            /// Read the service state variables, which does not change the service state, and thus
            /// allowed for instance funcs.
            pub struct InstanceContext {
                pub origin: Address,
                pub caller: Address,
                pub input: Bytes,
                pub service: Immutable<ServiceState>,
                pub instance: Mutable<InstanceState>,
            }
        }
    }
}

/// Defines service, instance, and UPC methods (functions) for a Lyquid contract.
///
/// ## Syntax: `lyquid::method!` Macro
///
/// The `lyquid::method!` macro defines functions within a Lyquid contract.
/// These methods may execute with service or instance context, and can also include UPC procedures.
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
///     constructor(<context>; <parameter_list>) {
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
///     <category> fn <method_name>(<context>; <parameter_list>) -> LyquidResult<ReturnType> {
///         // Function body
///     }
/// }
/// ```
///
/// #### Full Form (explicit group name):
///
/// ```ignore
/// lyquid::method! {
///     <category>(<group>) fn <method_name>(<context>; <parameter_list>) -> LyquidResult<ReturnType> {
///         // Function body
///     }
/// }
/// ```
///
/// ### UPC Definitions
///
/// #### Ergonomic UPC Form (syntactic sugar; expands to full forms below):
///
/// ```ignore
/// lyquid::method! {
///     upc <method_name>(<context>, <id>, <from>; <UPC_parameter_list>) -> ResultType: LyquidResult<ReturnType> {
///
///         callee {
///             // Returns a list of callees: LyquidResult<Vec<NodeID>>
///         }
///
///         request {
///             // Logic executed by each callee node when handling the UPC call.
///             // Returns: LyquidResult<ReturnType>
///         }
///
///         response {
///             // Aggregation logic executed by the calling node.
///             // Returns: Option<ReturnType>
///             //
///             // - Return `None` to indicate waiting for more responses.
///             // - Return `Some(value)` to finalize aggregation and terminate the UPC call.
///         }
///     }
/// }
/// ```
///
/// ### UPC (Full Form)
///
/// These expand the UPC lifecycle into three separate instance functions using dedicated groups.
///
/// #### 1. **UPC Callee Selection**
///
/// ```ignore
/// instance(upc_callee) fn <method_name>(<context>, <id>; <UPC_parameter_list>) -> LyquidResult<Vec<NodeID>> {
///     // Returns a list of NodeIDs representing the nodes to be invoked in this UPC instance.
/// }
/// ```
///
/// #### 2. **UPC Request Handler**
///
/// ```ignore
/// instance(upc_request) fn <method_name>(<context>, <id>, <from>; <UPC_parameter_list>) -> LyquidResult<ReturnType> {
///     // Executed by each callee node to perform the UPC-requested computation.
///
///     // Parameters:
///     // - `id`: Request ID (u64)
///     // - `from`: Caller's NodeID
/// }
/// ```
///
/// #### 3. **UPC Aggregator (Response Handler)**
///
/// ```ignore
/// instance(upc_response) fn <method_name>(<context>, <id>, <from>; response: LyquidResult<ReturnType>) -> LyquidResult<ReturnType> {
///     // Logic executed by the caller node to aggregate responses.
///
///     // Notes:
///     // - This is “client-side” logic, so it **does not access service or instance state**.
///     // - A temporary, volatile UPC-local context is available for aggregation purposes.
///     // - This context is discarded once the UPC call completes or errors.
/// }
/// ```
///
/// ### Notes on `<category>` and `<context>`
///
/// #### `<category>`:
///
/// - `service`:
///   A **consensus (sequencer) event-driven function** executed deterministically by all nodes hosting the same Lyquid.  
///   It operates on **service state**, which is shared and versioned across all nodes.
///
///   Service functions can **read and write `service` state**, and their execution is included in the contract's consensus logic. UPC, and other builtins that involve interaction with nondeterminism are not available in service functions.
///
/// - `instance`:
///   An **external event-driven function**, typically triggered by nondeterministic events such as **UPC calls**, **network messages**, or **timers**.  
///   These functions operate on **instance-local state**, which is specific to each node instance.
///
///   Instance functions can **read/write `instance` state**, and **read `service` state**, but they **can not mutate shared `service` state** — to avoid nondeterminism. They can also initiate a UPC call and invoke other bultins that involve nondeterminism.
///
/// #### `<context>`:
///
/// The `context` identifier (commonly `ctx`, but you can use your own choice such as `self`)
/// provides access to runtime state within the function.
///
/// - For `service` functions: the context is typed as `__lyquid::ServiceContext`  
/// - For `instance` functions: the context is typed as `__lyquid::InstanceContext`
///
/// Typical access patterns:
/// ```ignore
/// ctx.service.my_service_state_var
/// ctx.instance.my_instance_state_var
/// ```
///
/// See [state] for more information on how service and instance states are defined and accessed.
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
    ({service($event:ident) fn $fn:ident($handle:ident; $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($service_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*}, // recurisvely categorize the rest of the funcs
            {$($service_funcs)* // append this func to the end of service_funcs
                $event fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::ServiceContext {
                        origin: ctx.origin,
                        caller: ctx.caller,
                        input: ctx.input,
                        service: __lyquid::Mutable::new(__lyquid::ServiceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?)
                    };
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

    ({service fn $($rest:tt)*},
     {$($service_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({service(main) fn $($rest)*}, {$($service_funcs)*}, {$($instance_funcs)*}); };

    ({constructor($handle:ident; $($name:ident: $type:ty),*) $body:block $($rest:tt)*},
     {$($service_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({
        service(main) fn __lyquid_constructor($handle; $($name: $type),*) -> LyquidResult<bool> {$body; Ok(true)} $($rest)*}, {$($service_funcs)*}, {$($instance_funcs)*}); };

    ({instance(upc_callee) fn $fn:ident($handle:ident, $id:ident) -> LyquidResult<Vec<NodeID>> $body:block $($rest:tt)*},
     {$($service_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($service_funcs)*},
            {$($instance_funcs)*
                // see CalleeInput
                upc_callee fn $fn(id: u64) -> LyquidResult<Vec<NodeID>> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::InstanceContext {
                        origin: ctx.origin,
                        caller: ctx.caller,
                        input: ctx.input,
                        service: __lyquid::Immutable::new(__lyquid::ServiceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?),
                        instance: __lyquid::Mutable::new(__lyquid::InstanceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?)
                    };
                    let $id = id;
                    let result = $body;
                    drop($handle);
                    result
                }}
            }
        );
    };
    ({instance(upc_request) fn $fn:ident($handle:ident, $id:ident, $from:ident; $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($service_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($service_funcs)*},
            {$($instance_funcs)*
                // see RequestInput
                upc_request fn $fn(from: $crate::NodeID, id: u64, input: Vec<u8>) -> LyquidResult<$rt> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::InstanceContext {
                        origin: ctx.origin,
                        caller: ctx.caller,
                        input: ctx.input,
                        service: __lyquid::Immutable::new(__lyquid::ServiceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?),
                        instance: __lyquid::Mutable::new(__lyquid::InstanceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?)
                    };
                    let $id = id;
                    let $from = from;
                    let input = $crate::lyquor_primitives::decode_by_fields!(&input, $($name: $type),*).ok_or($crate::LyquidError::LyquorInput)?;
                    $(let $name = input.$name;)*
                    let result = $body;
                    drop($handle);
                    result
                }}
            }
        );
    };
    ({instance(upc_response) fn $fn:ident($handle:ident, $id:ident, $from:ident; $returned:ident: LyquidResult<$rt:ty>) -> LyquidResult<Option<$rt_:ty>> $body:block $($rest:tt)*},
     {$($service_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($service_funcs)*},
            {$($instance_funcs)*
                // see ResponseInput
                upc_response fn $fn(from: $crate::NodeID, id: u64, returned: Vec<u8>) -> LyquidResult<Option<Vec<u8>>> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::InstanceContext {
                        origin: ctx.origin,
                        caller: ctx.caller,
                        input: ctx.input,
                        service: __lyquid::Immutable::new(__lyquid::ServiceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?),
                        instance: __lyquid::Mutable::new(__lyquid::InstanceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?)
                    };
                    let $id = id;
                    let $from = from;
                    let $returned = $crate::lyquor_primitives::decode_object::<LyquidResult<$rt>>(&returned).ok_or($crate::LyquidError::LyquorInput)?;
                    let result = $body;
                    drop($handle);
                    // turn the inner returned user-supplied objec into serialized form so the
                    // caller can pass it on without knowing the type
                    result.map(|r| r.map(|r| Vec::from(&$crate::lyquor_primitives::encode_object(&r)[..])))
                }}
            }
        );
    };
    ({instance($event:tt) fn $fn:ident($handle:ident; $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($service_funcs:tt)*},
     {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($service_funcs)*},
            {$($instance_funcs)*
                $event fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::InstanceContext {
                        origin: ctx.origin,
                        caller: ctx.caller,
                        input: ctx.input,
                        service: __lyquid::Immutable::new(__lyquid::ServiceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?),
                        instance: __lyquid::Mutable::new(__lyquid::InstanceState::new(
                                &PrefixedAccess::new(Vec::from($crate::VAR_CATALOG_PREFIX)))?)
                    };
                    let result = $body;
                    drop($handle);
                    result
                }}
            }
        );
    };
    ({instance $($rest:tt)*},
     {$($service_funcs:tt)*},
     {$($instance_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance(main) $($rest)*}, {$($service_funcs)*}, {$($instance_funcs)*}); };

    // UPC implementation syntax sugar
    ({upc $fn:ident($handle:ident, $id:ident, $from:ident; $($name:ident: $type:ty),*) -> $result:ident: LyquidResult<$rt:ty> { callee $method_body:block $($upc_body_rest:tt)* } $($rest:tt)*},
    {$($service_funcs:tt)*},
    {$($instance_funcs:tt)*}) => {
       $crate::__lyquid_categorize_methods!(
           {$($rest)*
                instance(upc_callee) fn $fn($handle, $id) -> LyquidResult<Vec<NodeID>> $method_body
                upc $fn($handle, $id, $from; $($name: $type),*) -> $result: LyquidResult<$rt> { $($upc_body_rest)* }
           },
           {$($service_funcs)*},
           {$($instance_funcs)*}
       );
    };
    ({upc $fn:ident($handle:ident, $id:ident, $from:ident; $($name:ident: $type:ty),*) -> $result:ident: LyquidResult<$rt:ty> { request $method_body:block $($upc_body_rest:tt)* } $($rest:tt)*},
    {$($service_funcs:tt)*},
    {$($instance_funcs:tt)*}) => {
       $crate::__lyquid_categorize_methods!(
           {$($rest)*
                instance(upc_request) fn $fn($handle, $id, $from; $($name: $type),*) -> LyquidResult<$rt> $method_body
                upc $fn($handle, $id, $from; $($name: $type),*) -> $result: LyquidResult<$rt> { $($upc_body_rest)* }
           },
           {$($service_funcs)*},
           {$($instance_funcs)*}
       );
    };
    ({upc $fn:ident($handle:ident, $id:ident, $from:ident; $($name:ident: $type:ty),*) -> $result:ident: LyquidResult<$rt:ty> { response $method_body:block $($upc_body_rest:tt)* } $($rest:tt)*},
    {$($service_funcs:tt)*},
    {$($instance_funcs:tt)*}) => {
       $crate::__lyquid_categorize_methods!(
           {$($rest)*
                instance(upc_response) fn $fn($handle, $id, $from; $result: LyquidResult<$rt>) -> LyquidResult<Option<$rt>> $method_body
                upc $fn($handle, $id, $from; $($name: $type),*) -> $result: LyquidResult<$rt> { $($upc_body_rest)* }
           },
           {$($service_funcs)*},
           {$($instance_funcs)*}
       );
    };
    ({upc $fn:ident($handle:ident, $id:ident, $from:ident; $($name:ident: $type:ty),*) -> $result:ident: LyquidResult<$rt:ty> {} $($rest:tt)*},
    {$($service_funcs:tt)*},
    {$($instance_funcs:tt)*}) => {
       $crate::__lyquid_categorize_methods!(
           {$($rest)*},
           {$($service_funcs)*},
           {$($instance_funcs)*}
       );
    };
    ({}, {$($service_funcs:tt)*}, {$($instance_funcs:tt)*}) => {
        $crate::__lyquid_wrap_methods!("__lyquid_method_service", $($service_funcs)*);
        $crate::__lyquid_wrap_methods!("__lyquid_method_instance", $($instance_funcs)*);
    }
}

/// Transform a user-defined WASM function into a Lyquid function that can be invoked by the host.
#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_wrap_methods {
    ($prefix:tt, $event:tt fn $fn:ident($($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*) => {
        #[$crate::runtime::internal::prefix_name($prefix, $event)]
        mod $fn {
            use super::*;
            use alloy_dyn_abi::{DynSolType, DynSolValue};
            use $crate::runtime::*;
            use $crate::runtime::internal::*;
            use $crate::lyquor_primitives::{encode_object, decode_object, decode_by_fields};

            #[inline(always)]
            fn gen_type_string(form: u8) -> Option<String> {
                // assemble eth abi string for each parameter
                gen_eth_type_string::<$rt>(form,
                    [$((<$type as EthABI>::type_string(), <$type as EthABI>::is_scalar())),*].into_iter())
            }

            #[prefix_name($prefix, "ethabi", $event)]
            #[unsafe(no_mangle)]
            fn $fn(base: u32, len: u32, _: u32) -> u64 {
                let raw = unsafe { HostInput::new(base, len) };
                let decl: Option<u8> = decode_object(&raw);
                drop(raw);
                output_to_host(&encode_object(&decl.and_then(gen_type_string)))
            }

            #[prefix_name($prefix, $event)]
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
        }

        $crate::__lyquid_wrap_methods!($prefix, $($rest)*);
    };
    ($prefix:tt,) => {}
}
