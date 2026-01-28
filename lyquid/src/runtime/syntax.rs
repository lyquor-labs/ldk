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
/// You may define network/instance variables using any primitive types or nested user-defined structs.
/// Standard collections like `Vec`, `HashMap`, etc. can be used directly.
///
/// If you're using **third-party data structures**, they should just work.
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
/// - `network: lyquid::runtime::Mutable<NetworkState>` – access to your `network` state variables
///
/// #### `__lyquid::InstanceContext` (used in `instance` functions):
///
/// - `origin: Address` - this will always be the same as `caller`
/// - `caller: Address` - external caller
/// - `input: Bytes`  
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
///     // A byte vector for network state
///     arr: Vec<u8>,
///     x: u64,
///     y: u64,
/// }
///
/// struct MyNestedData {
///     entries: Vec<MyData>,
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
    {$($token:tt)*} => {
        __lyquid_state_preprocess!({$($token)*}, {});
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_state_preprocess {
    ({}, {$($token:tt)*}) => { __lyquid_state_generate!($($token)*); };
    ({network oracle $var:ident; $($rest:tt)*}, {$($token:tt)*}) => {
        __lyquid_state_preprocess!({$($rest)*}, {(oracle $var) $($token)*});
    };
    ({$cat:ident $var:ident: $type:ty = $init:expr; $($rest:tt)*}, {$($token:tt)*}) => {
        __lyquid_state_preprocess!({$($rest)*}, {($cat $var $type $init) $($token)*});
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_state_generate {
    ($($token:tt)*) => {
        pub mod __lyquid {
            use super::*;
            use $crate::runtime::*;

            struct NetworkAlloc;
            struct InstanceAlloc;

            internal::setup_lyquid_state_variables!(
                State
                __lyquid_initialize_state_variables
                [(network NetworkAlloc Network StateCategory::Network)
                (instance InstanceAlloc Instance StateCategory::Instance)] $($token)*);

            pub type NetworkContext = $crate::runtime::NetworkContextImpl<NetworkState>;
            pub type ImmutableNetworkContext = $crate::runtime::ImmutableNetworkContextImpl<NetworkState>;
            pub type InstanceContext = $crate::runtime::InstanceContextImpl<NetworkState, InstanceState>;
            pub type ImmutableInstanceContext = $crate::runtime::ImmutableInstanceContextImpl<NetworkState, InstanceState>;
            pub type UpcPrepareContext = $crate::runtime::upc::PrepareContextImpl<NetworkState>;
            pub type UpcRequestContext = $crate::runtime::upc::RequestContextImpl<NetworkState, InstanceState>;
            pub type UpcResponseContext = $crate::runtime::upc::ResponseContextImpl<NetworkState>;
        }
    }
}

/// Defines network, instance, and UPC methods (functions) for a Lyquid contract.
#[deprecated(
    since = "0.0.1",
    note = "use #[lyquid::method::network] or #[lyquid::method::instance] instead"
)]
#[macro_export]
macro_rules! method {
    {$($rest:tt)*} => {
        $crate::__lyquid_categorize_methods!({$($rest)*}, {}, {}, {});
    }
}

/// Categorize user-defined functions by their category keywords and transform them into Lyquid
/// functions.
#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_categorize_methods {
    ({network(oracle::certified::$first:ident $(:: $tail:ident)*) export($export:tt) fn $fn:ident(&mut $handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*}, // recurisvely categorize the rest of the funcs
            {$($network_funcs)* // append this func to the end of network_funcs
                oracle::certified::$first $(:: $tail)* (true, $export) fn $fn(oc: $crate::runtime::oracle::OracleCert, input_raw: $crate::Bytes) -> LyquidResult<$rt> {|ctx: CallContext| -> LyquidResult<$rt> {
                    let topic = concat!(stringify!($first), $( "::", stringify!($tail) ),*);
                    let params = CallParams {
                        origin: ctx.origin,
                        caller: ctx.caller,
                        group: topic.to_string(),
                        method: stringify!($fn).to_string(),
                        input: input_raw.clone(),
                        abi: $crate::lyquor_primitives::InputABI::Lyquor,
                    };
                    let me = ctx.lyquid_id;
                    let mut $handle = crate::__lyquid::NetworkContext::new(ctx)?;

                    if !$handle.network.__internal.oracle_dest(topic).verify(me, params, oc) {
                        return Err(LyquidError::InputCert)
                    }

                    let input = $crate::lyquor_primitives::decode_by_fields!(&input_raw, $($name: $type),*).ok_or(LyquidError::LyquorInput)?;
                    $(let $name = input.$name;)*
                    let result = $body; // execute the body of the function
                    drop($handle); // drop the state handle here to ensure the correct lifetime
                                   // for the handle when accessed in $body so the handle is not
                                   // leaked out by the result
                    result
                }}
            },
            {$($instance_funcs)*}, // retain the collected instance_funcs
            {$($internal_funcs)*}
        );
    };

    ({network($($group:ident)::*) export($export:tt) fn $fn:ident(&mut $handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*}, // recurisvely categorize the rest of the funcs
            {$($network_funcs)* // append this func to the end of network_funcs
                $($group)::* (true, $export) fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| -> LyquidResult<$rt> {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::NetworkContext::new(ctx)?;
                    let result = $body; // execute the body of the function
                    drop($handle); // drop the state handle here to ensure the correct lifetime
                                   // for the handle when accessed in $body so the handle is not
                                   // leaked out by the result
                    result
                }}
            },
            {$($instance_funcs)*}, // retain the collected instance_funcs
            {$($internal_funcs)*}
        );
    };

    ({network($($group:ident)::*) export($export:tt) fn $fn:ident(&$handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*}, // recurisvely categorize the rest of the funcs
            {$($network_funcs)* // append this func to the end of network_funcs
                $($group)::* (false, $export) fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| -> LyquidResult<$rt> {
                    use crate::__lyquid;
                    let $handle = __lyquid::ImmutableNetworkContext::new(ctx)?;
                    let result = $body; // execute the body of the function
                    drop($handle); // drop the state handle here to ensure the correct lifetime
                                   // for the handle when accessed in $body so the handle is not
                                   // leaked out by the result
                    result
                }}
            },
            {$($instance_funcs)*}, // retain the collected instance_funcs
            {$($internal_funcs)*}
        );
   };

    // Network function syntax sugar
    ({network fn $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({network(main) export(false) fn $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    ({network($($group:ident)::*) export($export:tt) fn $fn:ident(&mut $handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({network($($group)::*) export($export) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    ({network($($group:ident)::*) export($export:tt) fn $fn:ident(&$handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({network($($group)::*) export($export) fn $fn(&$handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    ({network($($group:ident)::*) fn $fn:ident(&mut $handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({network($($group)::*) export(false) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    ({network($($group:ident)::*) fn $fn:ident(&$handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({network($($group)::*) export(false) fn $fn(&$handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    ({constructor($($args:tt)*) $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({
        network(main) export(false) fn __lyquid_constructor($($args)*) -> LyquidResult<bool> {$body; Ok(true)} $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    // Syntactic sugar for UPC functions.
    ({upc($role:ident$($group:tt)*) $($rest:tt)*}, {$($network_funcs:tt)*}, {$($instance_funcs:tt)*}, {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!({instance(upc::$role$($group)*) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*});
    };

    ({instance(upc::prepare$($group:tt)*) fn $fn:ident(&$handle:ident) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                // see PrepareInput
                upc::prepare$($group)* (true, false) fn $fn(client_params: $crate::lyquor_primitives::Bytes) -> LyquidResult<$crate::upc::PrepareOutput> {|ctx: CallContext| -> LyquidResult<$crate::upc::PrepareOutput> {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::UpcPrepareContext::new(ctx)?;
                    let result: LyquidResult<Vec<NodeID>> = (|| {$body})();
                    let cache = $handle.cache.take_cache();
                    drop($handle);
                    result.map(|r| $crate::upc::PrepareOutput {
                        result: r,
                        cache: cache.map(|c| Box::into_raw(c) as $crate::upc::CachePtr)
                    })
                }}
            },
            {$($internal_funcs)*}
        );
    };

    ({instance(upc::prepare$($group:tt)*) fn $fn:ident(&$handle:ident, $($params:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                // see PrepareInput
                upc::prepare$($group)* (true, false) fn $fn(client_params: $crate::lyquor_primitives::Bytes) -> LyquidResult<$crate::upc::PrepareOutput> {|ctx: CallContext| -> LyquidResult<$crate::upc::PrepareOutput> {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::UpcPrepareContext::new(ctx)?;
                    let input = $crate::lyquor_primitives::decode_by_fields!(&client_params, $($params: $type),*).ok_or(LyquidError::LyquorInput)?;
                    $(let $params = input.$params;)*
                    let result: LyquidResult<Vec<NodeID>> = (|| {$body})();
                    let cache = $handle.cache.take_cache();
                    drop($handle);
                    result.map(|r| $crate::upc::PrepareOutput {
                        result: r,
                        cache: cache.map(|c| Box::into_raw(c) as $crate::upc::CachePtr)
                    })
                }}
            },
            {$($internal_funcs)*}
        );
    };

    ({instance(upc::request$($group:tt)*) fn $fn:ident(&mut $handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                // see RequestInput
                upc::request$($group)* (true, false) fn $fn(from: $crate::NodeID, id: u64, input: Vec<u8>) -> LyquidResult<$rt> {|ctx: CallContext| -> LyquidResult<$rt> {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::UpcRequestContext::new(ctx, from, id)?;
                    let input = $crate::lyquor_primitives::decode_by_fields!(&input, $($name: $type),*).ok_or(LyquidError::LyquorInput)?;
                    $(let $name = input.$name;)*
                    let result = $body;
                    drop($handle);
                    result
                }}
            },
            {$($internal_funcs)*}
        );
    };
    ({instance(upc::request$($group:tt)*) fn $fn:ident(&mut $handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance(upc::request$($group)*) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    // TODO: handle immutable UPC request correctly
    ({instance(upc::request$($group:tt)*) fn $fn:ident(&$handle:ident, $($name:ident: $type:ty),*) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance(upc::request$($group)*) fn $fn(&mut $handle, $($name: $type),*) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };
    ({instance(upc::request$($group:tt)*) fn $fn:ident(&$handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance(upc::request$($group)*) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    ({instance(upc::response$($group:tt)*) fn $fn:ident(&$handle:ident, $returned:ident: LyquidResult<$rt:ty>) -> LyquidResult<Option<$rt_:ty>> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                // see ResponseInput
                upc::response$($group)* (true, false) fn $fn(from: $crate::NodeID, id: u64, returned: Vec<u8>, cache: Option<$crate::upc::CachePtr>) -> LyquidResult<$crate::upc::ResponseOutput> {|ctx: CallContext| -> LyquidResult<$crate::upc::ResponseOutput> {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::UpcResponseContext::new(ctx, from, id, cache)?;
                    let $returned = $crate::lyquor_primitives::decode_object::<LyquidResult<$rt>>(&returned).ok_or(LyquidError::LyquorInput)?;
                    let result: LyquidResult<Option<$rt_>> = (|| {$body})();
                    let cache = $handle.cache.take_cache();
                    drop($handle);
                    result.map(|r|
                        match r {
                            // turn the inner returned user-supplied object into serialized form so the caller can pass it on without knowing the type
                            Some(r) => $crate::upc::ResponseOutput::Return(Vec::from(&$crate::lyquor_primitives::encode_object(&r)[..])),
                            // turn te cache into raw pointer so it won't be dropped
                            None => $crate::upc::ResponseOutput::Continue(cache.map(|c| Box::into_raw(c) as $crate::upc::CachePtr)),
                        })
                }}
            },
            {$($internal_funcs)*}
        );
    };

    ({instance(oracle::two_phase::$name:ident) export($export:tt) fn aggregate(&$handle:ident) -> LyquidResult<Option<CertifiedCallParams>> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
         $crate::__lyquid_categorize_methods!({$($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*},
         {$($internal_funcs)*
             #[$crate::runtime::internal::prefix_item("__lyquid_method_instance", (oracle::two_phase::$name))]
             #[unsafe(no_mangle)]
             pub fn aggregate(ctx: $crate::runtime::oracle::ProposalAggregationContext) -> LyquidResult<Option<CertifiedCallParams>> {
                 // TODO: impl ProposalAggregationContext properly, like those in upc.rs.
                 let $handle = ctx;
                 $body
             }
             $crate::__lyquid_emit_method_info!(
                 "__lyquid_method_instance",
                 (oracle::two_phase::$name),
                 false,
                 aggregate
             );
         });
    };

    ({instance(oracle::two_phase::$name:ident$($group:tt)*) export($export:tt) fn propose(&mut $handle:ident, $($params:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
         $crate::__lyquid_categorize_methods!({
            instance(upc::prepare::oracle::two_phase::$name$($group)*) fn propose(
                &ctx,
                callee: Vec<NodeID>,
                init: $crate::lyquor_primitives::Bytes
            ) -> LyquidResult<Vec<NodeID>> {
                ctx.cache.set($crate::runtime::oracle::ProposalAggregation::new(init));
                Ok(callee)
            }

            instance(upc::response::oracle::two_phase::$name$($group)*) fn propose(
                &ctx,
                resp: LyquidResult<$crate::runtime::oracle::ProposeResponse>
            ) -> LyquidResult<Option< Option<$crate::runtime::oracle::Proposal> >> {
                let cache: &mut $crate::runtime::oracle::ProposalAggregation =
                    ctx.cache.get_mut().expect("Oracle: proposal aggregation cache should have been set.");
                if let Ok(resp) = resp {
                    return Ok(cache.add_response(
                        ctx.from,
                        resp,
                        &ctx.network.$name,
                        prefix_call!(("__lyquid_method_instance", (oracle::two_phase::$name)), aggregate),
                        ctx.lyquid_id))
                }
                Ok(None)
            }

            instance(upc::request::oracle::two_phase::$name$($group)*) fn propose(
                &mut ctx,
                msg: $crate::runtime::oracle::ProposeRequest
            ) -> LyquidResult<$crate::runtime::oracle::ProposeResponse> {
                let $handle = &mut ctx;
                let input = $crate::lyquor_primitives::decode_by_fields!(&msg.init, $($params: $type),*)
                    .ok_or(LyquidError::LyquorInput)?;
                $(let $params = input.$params;)*
                let result: $rt = $body?;
                let result = $crate::lyquor_primitives::Bytes::from($crate::lyquor_primitives::encode_object(&result));
                ctx.network.$name.__post_propose(msg.init, result)
            }

            instance(oracle::single_phase::$name::two_phase$($group)*) export(false) fn validate(&mut ctx, params: CallParams, extra: Bytes) -> LyquidResult<bool> {
                let extra = match $crate::lyquor_primitives::decode_by_fields!(&extra,
                    init: Bytes,
                    inputs: Vec<$crate::runtime::oracle::ProposalInput>
                ) {
                    Some(extra) => extra,
                    None => return Ok(false),
                };
                for input in &extra.inputs {
                    if !input.verify(extra.init.clone(), ctx.network.$name)? {
                        return Ok(false)
                    }
                }

                let agg_ctx = $crate::runtime::oracle::ProposalAggregationContext {
                    init: &extra.init,
                    inputs: &extra.inputs,
                    lyquid_id: ctx.lyquid_id,
                };

                let output = prefix_call!(("__lyquid_method_instance", (oracle::two_phase::$name)), aggregate(agg_ctx))?;
                let _params = match output {
                    Some(o) => o,
                    None => return Ok(false),
                };
                Ok(params.origin == _params.origin &&
                    params.caller == _params.origin &&
                    params.method == _params.method &&
                    params.input == _params.input)
            }

            $($rest)*
         }, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*});
     };

    ({instance(oracle::single_phase::$name:ident$($group:tt)*) export($export:tt) fn validate(&mut $handle:ident, $params:ident: CallParams, $extra:ident: Bytes) -> LyquidResult<bool> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
         $crate::__lyquid_categorize_methods!({
            instance(upc::prepare::oracle::single_phase::$name$($group)*) fn validate(
                &ctx, callee: Vec<NodeID>,
                header: $crate::runtime::oracle::OracleHeader,
                yay_msg: $crate::lyquor_primitives::Bytes,
                nay_msg: $crate::lyquor_primitives::Bytes
            ) -> LyquidResult<Vec<NodeID>> {
                ctx.cache.set($crate::runtime::oracle::ValidateAggregation::new(
                    header, yay_msg, nay_msg));
                Ok(callee)
            }

            instance(upc::response::oracle::single_phase::$name$($group)*) fn validate(
                &ctx,
                resp: LyquidResult<$crate::runtime::oracle::ValidateResponse>
            ) -> LyquidResult<Option< Option<$crate::runtime::oracle::OracleCert> >> {
                let cache: &mut $crate::runtime::oracle::ValidateAggregation =
                    ctx.cache.get_mut().expect("Oracle: aggregation cache should have been set.");
                if let Ok(resp) = resp {
                    return Ok(cache.add_response(ctx.from, resp, &ctx.network.$name))
                }
                Ok(None)
            }

            instance(upc::request::oracle::single_phase::$name$($group)*) fn validate(
                &mut ctx,
                msg: $crate::runtime::oracle::ValidateRequest
            ) -> LyquidResult<$crate::runtime::oracle::ValidateResponse> {
                // TODO: check if msg.proposer matches the UPC sender.

                if !ctx.network.$name.__pre_validation(&msg.header) {
                    return Err(LyquidError::LyquidRuntime("Mismatch config".into()))
                }

                let approval = (|| -> LyquidResult<bool> {
                    let $params = msg.params.clone();
                    let $extra = msg.extra;
                    let $handle = &mut ctx;
                    $body
                })()?;

                ctx.network.$name.__post_validation(msg.header, msg.params, approval)
            }

            $($rest)*
         }, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*});
     };


    ({instance($($group:ident)::*) export($export:tt) fn $fn:ident(&mut $handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                $($group)::* (true, $export) fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| -> LyquidResult<$rt> {
                    use crate::__lyquid;
                    let mut $handle = __lyquid::InstanceContext::new(ctx)?;
                    let result = $body;
                    drop($handle);
                    result
                }}
            },
            {$($internal_funcs)*}
        );
    };
    ({instance($($group:ident)::*) export($export:tt) fn $fn:ident(&$handle:ident, $($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => {
        $crate::__lyquid_categorize_methods!(
            {$($rest)*},
            {$($network_funcs)*},
            {$($instance_funcs)*
                $($group)::* (false, $export) fn $fn($($name: $type),*) -> LyquidResult<$rt> {|ctx: CallContext| -> LyquidResult<$rt> {
                    use crate::__lyquid;
                    let $handle = __lyquid::ImmutableInstanceContext::new(ctx)?;
                    let result = $body;
                    drop($handle);
                    result
                }}
            },
            {$($internal_funcs)*}
        );
    };
    ({instance($($group:ident)::*) export($export:tt) fn $fn:ident(&mut $handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance($($group)::*) export($export) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };
    ({instance($($group:ident)::*) export($export:tt) fn $fn:ident(&$handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance($($group)::*) export($export) fn $fn(&$handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    ({instance($($group:ident)::*) fn $fn:ident(&mut $handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance($($group)::*) export(false) fn $fn(&mut $handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };
    ({instance($($group:ident)::*) fn $fn:ident(&$handle:ident) $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance($($group)::*) export(false) fn $fn(&$handle,) $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    // instance function syntax sugar
    ({instance fn $($rest:tt)*},
     {$($network_funcs:tt)*},
     {$($instance_funcs:tt)*},
     {$($internal_funcs:tt)*}) => { $crate::__lyquid_categorize_methods!({instance(main) export(false) fn $($rest)*}, {$($network_funcs)*}, {$($instance_funcs)*}, {$($internal_funcs)*}); };

    ({}, {$($network_funcs:tt)*}, {$($instance_funcs:tt)*}, {$($internal_funcs:tt)*}) => {
        const _: () = {
            use $crate::LyquidError;
            $crate::__lyquid_wrap_methods!("__lyquid_method_network", $($network_funcs)*);
            $crate::__lyquid_wrap_methods!("__lyquid_method_instance", $($instance_funcs)*);
        };

        $($internal_funcs)*
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_method_alias {
    ("__lyquid_method_network" $($group:ident)::* (false) $fn:ident) => {
        $crate::__lyquid_emit_method_info!("__lyquid_method_instance", ($($group)::*) , false, $fn);

        #[prefix_item("__lyquid_method_instance", ($($group)::*))]
        #[unsafe(no_mangle)]
        fn $fn(base: u32, len: u32, abi: u32) -> u64 {
            prefix_call!(("__lyquid_method_network", ($($group)::*)), $fn(base, len, abi))
        }
    };
    ("__lyquid_method_network" $($group:ident)::* (true) $fn:ident) => {};
    ("__lyquid_method_instance" $($group:ident)::* (false) $fn:ident) => {};
    ("__lyquid_method_instance" $($group:ident)::* (true) $fn:ident) => {};
}

// TODO: move this macro to primitives crate instead
#[macro_export]
macro_rules! decode_eth_params {
    ($input:expr, $($name:ident: $type:ty),*) => {
        (|| -> Option<($($type,)*)> {
            use $crate::alloy_dyn_abi::{DynSolType, DynSolValue};
            use $crate::runtime::EthAbiValue;
            use $crate::runtime::ethabi::{EthAbiType, dyn_sol_type};

            let sol_type = DynSolType::Tuple(vec![
                $(dyn_sol_type(<$type as EthAbiType>::DESC)?,)*
            ]);
            let decoded = sol_type.abi_decode_params($input).ok()?;

            let mut iter = match decoded {
                DynSolValue::Tuple(v) => v.into_iter(),
                _ => return None,
            };

            Some(($(<$type as EthAbiValue>::decode(iter.next()?)?,)*))
        })()
    };
}

#[macro_export]
macro_rules! encode_eth_params {
    ($($val:expr),*) => {
        {
            use $crate::alloy_dyn_abi::DynSolValue;
            use $crate::runtime::EthAbiValue;
            use $crate::Bytes;
            let vals = vec![$($val.encode()),*];
            Bytes::from(DynSolValue::Tuple(vals).abi_encode_params())
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_group_string {
    ($single:ident) => {
        stringify!($single)
    };
    ($head:ident :: $($tail:ident)::+) => {
        concat!(stringify!($head), "::", $crate::__lyquid_group_string!($($tail)::+))
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_method_category {
    ("__lyquid_method_network") => {
        $crate::consts::CATEGORY_NETWORK
    };
    ("__lyquid_method_instance") => {
        $crate::consts::CATEGORY_INSTANCE
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_emit_method_info {
    ($prefix:tt, ($($group:ident)::*) , $mutable:tt, $fn:ident) => {
        #[doc(hidden)]
        const _: () = {
            const GROUP: &str = $crate::__lyquid_group_string!($($group)::*);
            const METHOD: &str = stringify!($fn);
            const LEN: usize = $crate::consts::info_len(GROUP, METHOD);
            #[unsafe(link_section = "lyquor.method.info")]
            #[used]
            static INFO: [u8; LEN] = $crate::consts::info_encode::<LEN>(
                $crate::__lyquid_method_category!($prefix),
                $mutable,
                GROUP,
                METHOD,
            );
        };
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_invoke_lyquor {
    ($raw:ident, ($($name:ident: $type:ty),*), $rt:ty, $body:block) => {{
        let result = (|| -> Result<$rt, LyquidError> {
            let (input, ctx) = (|| {
                let ctx: $crate::CallContext = decode_object(&$raw)?;
                Some((decode_by_fields!(&ctx.input, $($name: $type),*)?, ctx))
            })().ok_or(LyquidError::LyquorInput)?;
            drop($raw);
            // set up the context so the function developer feels as if these parameters in
            // the input are real
            $(let $name = input.$name;)*
            // execute the function body
            ($body)(ctx)
        })();
        encode_object(&result)
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_emit_method_fn {
    (true, $prefix:tt, ($($group:ident)::*) , $fn:ident, ($($name:ident: $type:ty),*), $rt:ty, $body:block) => {
        #[prefix_item($prefix, ($($group)::*))]
        #[unsafe(no_mangle)]
        fn $fn(base: u32, len: u32, abi: u32) -> u64 {
            let raw = unsafe { HostInput::new(base, len) };
            let output = if abi == ABI_ETH {
                let result = (|| -> Result<$rt, LyquidError> {
                    let (input, ctx) = (|| {
                        let ctx: $crate::CallContext = decode_object(&raw)?;

                        // We cache the Solidity type decoder so Eth ABI types are only generated once
                        static SOL_TYPE_CACHED: std::sync::OnceLock<Option<$crate::alloy_dyn_abi::DynSolType>> =
                            std::sync::OnceLock::new();
                        let sol_type = SOL_TYPE_CACHED.get_or_init(|| {
                            let mut types = Vec::new();
                            $(
                                    let ty = $crate::runtime::ethabi::dyn_sol_type(
                                        <$type as $crate::runtime::ethabi::EthAbiType>::DESC
                                    )?;
                                types.push(ty);
                            )*
                            Some($crate::alloy_dyn_abi::DynSolType::Tuple(types))
                        }).as_ref()?;

                        // decode to a list of DynSolValue
                        let mut iter = match sol_type.abi_decode_params(&ctx.input).ok()? {
                            $crate::alloy_dyn_abi::DynSolValue::Tuple(v) => v.into_iter(),
                            _ => return None,
                        };
                        struct Parameters {$($name: $type),*}
                        // then let each type use its trait method to decode further
                        Some((Parameters {
                            $($name: <$type as EthAbiValue>::decode(iter.next()?)?),*
                        }, ctx))
                    })().ok_or(LyquidError::LyquorInput)?;
                    drop(raw);
                    // set up the context so the function developer feels as if these parameters in
                    // the input are real
                    $(let $name = input.$name;)*
                    // execute the function body
                    ($body)(ctx)
                })().map(|rt| {
                    let values = <$rt as EthAbiReturnValue>::encode_return(rt);
                    $crate::alloy_dyn_abi::DynSolValue::Tuple(values).abi_encode_sequence().unwrap()
                });
                encode_object(&result)
            } else {
                $crate::__lyquid_invoke_lyquor!(raw, ($($name: $type),*), $rt, $body)
            };
            // TODO: possible improvement to not copy this already WASM-allocated vector? But
            // need to make sure it can be properly deallocated.
            output_to_host(&output)
        }
    };
    (false, $prefix:tt, ($($group:ident)::*) , $fn:ident, ($($name:ident: $type:ty),*), $rt:ty, $body:block) => {
        #[prefix_item($prefix, ($($group)::*))]
        #[unsafe(no_mangle)]
        fn $fn(base: u32, len: u32, abi: u32) -> u64 {
            let _ = abi;
            let raw = unsafe { HostInput::new(base, len) };
            let output = $crate::__lyquid_invoke_lyquor!(raw, ($($name: $type),*), $rt, $body);
            // TODO: possible improvement to not copy this already WASM-allocated vector? But
            // need to make sure it can be properly deallocated.
            output_to_host(&output)
        }
    };
}

/// Transform a user-defined WASM function into a Lyquid function that can be invoked by the host.
#[doc(hidden)]
#[macro_export]
macro_rules! __lyquid_wrap_methods {
    ($prefix:tt, $($group:ident)::* ($mutable:tt, $export:tt) fn $fn:ident($($name:ident: $type:ty),*) -> LyquidResult<$rt:ty> $body:block $($rest:tt)*) => {
        $crate::__lyquid_emit_method_info!($prefix, ($($group)::*) , $mutable, $fn);

        #[$crate::runtime::internal::prefix_item($prefix, ($($group)::*))]
        mod $fn {
            use super::*;
            use $crate::runtime::*;
            use $crate::runtime::internal::*;
            use $crate::lyquor_primitives::{encode_object, decode_object, decode_by_fields};

            $crate::__lyquid_emit_method_fn!($export, $prefix, ($($group)::*) , $fn, ($($name: $type),*), $rt, $body);

            $crate::__lyquid_method_alias!($prefix $($group)::* ($mutable) $fn);
        }

        $crate::__lyquid_wrap_methods!($prefix, $($rest)*);
    };
    ($prefix:tt,) => {}
}
