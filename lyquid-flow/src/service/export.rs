/// Declares one direct-HTTP Flow service at a Lyquid crate's root.
///
/// Supply backend state and an initializer returning a Scope. Business input is collected by Steps.
/// `replace_existing` explicitly selects a single active execution.
/// This expands the state declaration, HTTP export, readiness method, and coalesced instance worker.
/// Applications must import `lyquid::prelude::*` and must not declare a second `state!` block.
#[macro_export]
macro_rules! serve_flow {
    (
        state { $($state:tt)* }
        replace_existing: $replace:expr;
        create($ctx:ident) $initialize:block
    ) => {
        lyquid::state! {
            instance flow_service: $crate::service::FlowService = $crate::service::FlowService::new();
            $($state)*
        }

        #[lyquid::method::instance(export = http, method = "*", path_prefix = "/api/flows")]
        fn flow_service_http($ctx: &_, request: lyquid::http::Request) -> lyquid::LyquidResult<lyquid::http::Response> {
            let service = $ctx.instance.flow_service.read().clone();
            Ok(service.serve(request, $replace, || $initialize, |_| {
                (|| -> lyquid::LyquidResult<()> {
                    lyquid::trigger!(flow_service_run(), lyquid::prelude::TriggerMode::Once(0));
                    Ok(())
                })().map_err(|error| error.to_string())
            }))
        }

        #[lyquid::method::instance]
        fn flow_service_run(ctx: &mut _) -> lyquid::LyquidResult<()> {
            let service = ctx.instance.flow_service.read().clone();
            service.run_pending().map_err(|error| lyquid::LyquidError::LyquidRuntime(format!("{error:?}")))
        }

        #[lyquid::method::instance(export = eth)]
        fn flow_service_ready(_ctx: &_) -> lyquid::LyquidResult<bool> {
            Ok(true)
        }
    };
}
