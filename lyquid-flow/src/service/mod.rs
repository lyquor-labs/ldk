//! Shared direct-HTTP Flow service. Applications create Scopes and schedule instance workers.
//!
//! Round identity lives here; Scope owns execution, retained input contracts, and commits.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use lyquid::{
    http,
    prelude::{HashMap, Mutex, new_hashmap},
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{FlowError, InputError, InputHandle, Scope, ScopeId, StepId};

mod export;
#[path = "http.rs"] mod transport;
pub use transport::{handle_http, json_response};

/// Public routing identity, unrelated to Scope/checkpoint IDs.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FlowClientId(pub String);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Processing,
    AwaitingInput,
    Completed,
    Failed,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StepInfo {
    pub id: StepId,
    pub description: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PendingInput {
    pub request_id: String,
    /// InputSpec's serializable fields only; no Value prototypes or decoders.
    pub spec: JsonValue,
    pub a2ui: Vec<JsonValue>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ResultView {
    pub spec: JsonValue,
    pub a2ui: Vec<JsonValue>,
}

/// One consistent, cached publication. Reading it never executes user code.
#[derive(Clone, Deserialize, Serialize)]
pub struct ReadResponse {
    pub revision: u64,
    pub status: Status,
    pub step: StepInfo,
    pub input: Option<PendingInput>,
    pub view: ResultView,
    pub error: Option<String>,
    pub history: History,
}

/// Application-selected checkpoints, published atomically with the current input and result.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct History {
    pub active_revision_id: Option<ScopeId>,
    pub revisions: Vec<Revision>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Revision {
    pub id: ScopeId,
    pub parent_id: Option<ScopeId>,
    /// Explicit application display metadata; never an implicit State or Trace export.
    pub data: JsonValue,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ClientError {
    Malformed { message: String },
    NotFound,
    NoPending,
    Stale,
    Invalid { fields: Vec<InputError> },
    Internal { message: String },
}

impl ClientError {
    fn internal(error: impl ToString) -> Self {
        Self::Internal {
            message: error.to_string(),
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Self::Malformed { .. } => 400,
            Self::NotFound => 404,
            Self::NoPending | Self::Stale => 409,
            Self::Invalid { .. } => 422,
            Self::Internal { .. } => 500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SubmitResponse {
    Accepted,
}

struct Execution {
    scope: Option<Scope>,
    input: InputHandle,
    published: ReadResponse,
    publication_error: Option<String>,
    round: u64,
    restoring: bool,
}

/// One registered standalone execution. Clones refer to the same owned Scope and publication.
#[derive(Clone)]
pub struct FlowClient {
    id: FlowClientId,
    execution: Arc<Mutex<Execution>>,
}

impl FlowClient {
    #[expect(
        clippy::arc_with_non_send_sync,
        reason = "Guest calls share atomic handles; Scope (including its observer) remains serialized and is not native-thread Send."
    )]
    fn new(id: FlowClientId, scope: Scope) -> Result<Self, ClientError> {
        // Registration publishes selected initial data without advancing the execution.
        let (step, view) = presentation(&id, &scope)?;
        Ok(Self {
            id,
            execution: Arc::new(Mutex::new(Execution {
                input: scope.input_handle(),
                scope: Some(scope),
                published: ReadResponse {
                    revision: 1,
                    status: Status::Processing,
                    step,
                    input: None,
                    view,
                    error: None,
                    history: History::default(),
                },
                publication_error: None,
                round: 0,
                restoring: false,
            })),
        })
    }

    pub fn read(&self) -> Result<ReadResponse, ClientError> {
        let execution = self.execution.lock();
        if let Some(error) = &execution.publication_error {
            return Err(ClientError::internal(error));
        }
        Ok(execution.published.clone())
    }

    /// Atomically checks the displayed round and consumes its retained contract exactly once.
    pub fn submit(&self, request_id: &str, values: &str) -> Result<SubmitResponse, ClientError> {
        let mut execution = self.execution.lock();
        if let Some(error) = &execution.publication_error {
            return Err(ClientError::internal(error));
        }
        let pending = execution.published.input.as_ref().ok_or(ClientError::NoPending)?;
        if pending.request_id != request_id {
            return Err(ClientError::Stale);
        }
        execution.input.submit_input(values).map_err(|error| match error {
            FlowError::InputInvalid(error) => ClientError::Invalid { fields: vec![error] },
            FlowError::NoPendingInput | FlowError::InputClosed => ClientError::NoPending,
            error => ClientError::internal(error),
        })?;
        execution.published.input = None;
        execution.published.status = Status::Processing;
        execution.published.error = None;
        execution.published.revision += 1;
        Ok(SubmitResponse::Accepted)
    }

    /// Called by the application's instance task after registration or acceptance.
    /// No registry or publication lock is held while models or Steps execute.
    /// Duplicate task delivery is harmless: only a processing, idle Scope can be taken.
    pub fn run(&self) -> Result<(), ClientError> {
        let mut scope = {
            let mut execution = self.execution.lock();
            if let Some(error) = &execution.publication_error {
                return Err(ClientError::internal(error));
            }
            if execution.published.status != Status::Processing {
                return Ok(());
            }
            let Some(scope) = execution.scope.take() else {
                return Ok(());
            };
            scope
        };
        let outcome = scope.run_until_input();
        let error = outcome.err().map(|error| error.to_string());
        if error.is_some() {
            // Do not execute a later Step or resubmit the consumed answer while preparing a retry.
            let _ = scope.retry_input();
        }
        let mut execution = self.execution.lock();
        let result = self.publish(&mut execution, &mut scope, error);
        execution.scope = Some(scope);
        if let Err(ClientError::Internal { message }) = &result {
            // The worker stopped. Keep the committed publication, but permit checkpoint recovery.
            execution.published.status = Status::Failed;
            execution.publication_error = Some(message.clone());
        }
        result
    }

    fn publish(&self, execution: &mut Execution, scope: &mut Scope, error: Option<String>) -> Result<(), ClientError> {
        let (step, view) = presentation(&self.id, scope)?;
        let round = execution.round + 1;
        let input = scope
            .input_handle()
            .input_spec()
            .map(|spec| {
                let request_id = format!("{}:{round}", self.id.0);
                let a2ui = spec
                    .ui()
                    .surface(&format!("{}:input:{round}", self.id.0), Some(&request_id))
                    .map_err(ClientError::internal)?;
                let spec = serde_json::to_value(spec).map_err(ClientError::internal)?;
                Ok(PendingInput { request_id, spec, a2ui })
            })
            .transpose()?;
        let status = if error.is_some() {
            Status::Failed
        } else if input.is_some() {
            Status::AwaitingInput
        } else {
            Status::Completed
        };
        let mut history = execution.published.history.clone();
        let previous = history
            .revisions
            .iter()
            .find(|revision| Some(&revision.id) == history.active_revision_id.as_ref())
            .map(|revision| &revision.data);
        let metadata = if status == Status::AwaitingInput && !execution.restoring {
            scope.history_metadata(previous).map_err(ClientError::internal)?
        } else {
            None
        };
        // Checkpoint only after every fallible projection succeeds, before exposing the input.
        if let Some(data) = metadata {
            let id = scope.checkpoint();
            history.revisions.push(Revision {
                id: id.clone(),
                parent_id: history.active_revision_id.clone(),
                data,
            });
            history.active_revision_id = Some(id);
        }
        // All fallible projection work completed. Replace the whole publication at once.
        execution.published = ReadResponse {
            revision: execution.published.revision + 1,
            status,
            step,
            input,
            view,
            error,
            history,
        };
        execution.round = round;
        execution.restoring = false;
        execution.publication_error = None;
        Ok(())
    }

    fn scheduling_failed(&self, error: String) -> ClientError {
        let message = format!("request accepted but scheduling failed: {error}");
        let mut execution = self.execution.lock();
        execution.published.status = Status::Failed;
        execution.published.error = Some(message.clone());
        execution.published.revision += 1;
        ClientError::internal(message)
    }

    /// Saves a manual Scope checkpoint. Automatic public history is selected by FlowBuilder::history.
    pub fn checkpoint(&self) -> Result<ScopeId, ClientError> {
        let mut execution = self.execution.lock();
        if execution.published.status == Status::Processing {
            return Err(ClientError::NoPending);
        }
        execution
            .scope
            .as_mut()
            .map(Scope::checkpoint)
            .ok_or(ClientError::NoPending)
    }

    /// Restoring invalidates the displayed round immediately. Schedule `run` to publish a new one.
    pub fn restore(&self, checkpoint: &ScopeId) -> Result<(), ClientError> {
        let mut execution = self.execution.lock();
        if execution.published.status == Status::Processing {
            return Err(ClientError::NoPending);
        }
        let scope = execution.scope.as_mut().ok_or(ClientError::NoPending)?;
        if !scope.checkpoint_ids().any(|id| id == checkpoint) {
            return Err(ClientError::NotFound);
        }
        scope.restore(checkpoint).map_err(ClientError::internal)?;
        execution.published.history.active_revision_id = execution
            .published
            .history
            .revisions
            .iter()
            .find(|revision| &revision.id == checkpoint)
            .map(|revision| revision.id.clone());
        execution.restoring = true;
        execution.published.input = None;
        execution.published.status = Status::Processing;
        execution.published.error = None;
        execution.published.revision += 1;
        execution.publication_error = None;
        Ok(())
    }
}

fn presentation(id: &FlowClientId, scope: &Scope) -> Result<(StepInfo, ResultView), ClientError> {
    let (_, step_id, step) = scope.presentation_step().map_err(ClientError::internal)?;
    let spec = scope.view().map_err(ClientError::internal)?;
    let a2ui = spec
        .ui()
        .surface(&format!("{}:view", id.0), None)
        .map_err(ClientError::internal)?;
    Ok((
        StepInfo {
            id: step_id,
            description: step.description(false),
        },
        ResultView {
            spec: serde_json::to_value(spec).map_err(ClientError::internal)?,
            a2ui,
        },
    ))
}

/// Standalone registry. A future Session resolver can use the same HTTP adapter and FlowClient.
#[derive(Clone)]
pub struct FlowService {
    clients: Arc<Mutex<HashMap<FlowClientId, FlowClient>>>,
}

impl Default for FlowService {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowService {
    #[expect(
        clippy::arc_with_non_send_sync,
        reason = "Guest state shares atomic client handles across calls; this does not make Scope native-thread Send."
    )]
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(new_hashmap())),
        }
    }

    /// Registers explicitly created business execution. The caller then schedules `FlowClient::run`.
    pub fn register(&self, scope: Scope) -> Result<FlowClientId, ClientError> {
        Ok(self.insert(scope, false)?.id)
    }

    /// Replaces this service's executions atomically after successful business initialization.
    pub fn replace(&self, scope: Scope) -> Result<FlowClientId, ClientError> {
        Ok(self.insert(scope, true)?.id)
    }

    fn insert(&self, scope: Scope, replace: bool) -> Result<FlowClient, ClientError> {
        use std::fmt::Write as _;
        let bytes = lyquid::prelude::lyquor_api::random_bytes(16).map_err(ClientError::internal)?;
        let mut id = String::new();
        for byte in bytes {
            write!(&mut id, "{byte:02x}").expect("writing to String");
        }
        // Entropy separates runtime incarnations; the counter prevents reuse within this runtime,
        // including deterministic hosts whose entropy provider returns the same bytes in tests.
        static NEXT_CLIENT: AtomicU64 = AtomicU64::new(1);
        let sequence = NEXT_CLIENT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| value.checked_add(1))
            .map_err(|_| ClientError::internal("Flow client IDs exhausted"))?;
        write!(&mut id, "-{sequence:x}").expect("writing to String");
        let id = FlowClientId(id);
        let client = FlowClient::new(id.clone(), scope)?;
        let mut clients = self.clients.lock();
        if replace {
            for (_, previous) in clients.drain() {
                previous.execution.lock().input.request_stop();
            }
        }
        clients.insert(id, client.clone());
        Ok(client)
    }

    /// Drain processing executions from a coalesced instance trigger. Lyquid triggers are keyed
    /// by function, not arguments, so applications should schedule one no-argument worker.
    /// Registrations/submissions during this pass schedule the next pass through the same trigger.
    pub fn run_pending(&self) -> Result<(), ClientError> {
        let clients = self.clients.lock().values().cloned().collect::<Vec<_>>();
        let mut first_error = None;
        for client in clients {
            if let Err(error) = client.run() {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub fn resolve(&self, id: &FlowClientId) -> Option<FlowClient> {
        self.clients.lock().get(id).cloned()
    }

    /// Retire an execution; replacement is a new registration and never reuses its client ID.
    pub fn remove(&self, id: &FlowClientId) {
        let client = self.clients.lock().remove(id);
        if let Some(client) = client {
            client.execution.lock().input.request_stop();
        }
    }

    pub fn handle_http(
        &self, request: http::Request, schedule: impl FnOnce(FlowClientId) -> Result<(), String>,
    ) -> http::Response {
        handle_http(request, |id| self.resolve(id), schedule)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use lyquid_test::test;
    use serde_json::json;

    use super::*;
    use crate::{
        AutoCheckpointConfig, Flow, InputSpec, State, StateNamespace, StateUpdates, Step, TemplateSpec, TraceSummary,
        TurnProposal, ViewSpec,
    };

    mod lifecycle {
        use std::cell::Cell;

        use lyquid_test::test;

        use super::*;

        fn history_scope(broken: bool) -> Scope {
            let mut flow = counter_flow(Arc::new(AtomicUsize::new(0)), false, false);
            flow.history = Some(if broken {
                |scope, _| {
                    if *scope.state().get::<u64>("count").unwrap() > 0 {
                        return Err(FlowError::Execution("history projection failed".into()));
                    }
                    Ok(Some(json!({"count": 0})))
                }
            } else {
                |scope, _| Ok(Some(json!({"count": scope.state().get::<u64>("count").unwrap()})))
            });
            scope(flow)
        }

        fn creation(body: &str) -> http::Request {
            http::Request {
                method: http::Method::Post,
                url: "/api/flows".into(),
                headers: vec![],
                body: Some(body.as_bytes().to_vec()),
            }
        }

        #[test]
        fn creation_and_replacement() {
            let service = FlowService::new();
            let initialized = Cell::new(0);
            let scheduled = Cell::new(0);
            let reject = Cell::new(false);
            let serve = |request| {
                service.serve(
                    request,
                    true,
                    || {
                        initialized.set(initialized.get() + 1);
                        if reject.get() {
                            return Err("backend initialization failed".into());
                        }
                        Ok(history_scope(false))
                    },
                    |_| {
                        scheduled.set(scheduled.get() + 1);
                        Ok(())
                    },
                )
            };
            let created = serve(creation(""));
            assert_eq!(created.status, 202);
            let created: JsonValue = serde_json::from_slice(&created.body).unwrap();
            assert_eq!(created.as_object().unwrap().len(), 1);
            let id: FlowClientId = serde_json::from_value(created["client_id"].clone()).unwrap();
            let client = service.resolve(&id).unwrap();
            assert_eq!(read(&client)["status"], "processing");
            assert!(read(&client)["history"]["revisions"].as_array().unwrap().is_empty());
            service.run_pending().unwrap();
            let before = read(&client);
            for _ in 0..2 {
                assert_eq!(serve(request(http::Method::Get, &id, "", "")).status, 200);
            }
            for body in [r#"{"request":"ignored?"}"#, "{}", "null", "invalid"] {
                let rejected = serve(creation(body));
                assert_eq!(rejected.status, 400);
                let rejected: JsonValue = serde_json::from_slice(&rejected.body).unwrap();
                assert_eq!(rejected["error"], "malformed");
            }
            let mut get = creation("");
            get.method = http::Method::Get;
            assert_eq!(serve(get).status, 404);
            assert_eq!(initialized.get(), 1);
            assert_eq!(scheduled.get(), 1);
            reject.set(true);
            assert_eq!(serve(creation("")).status, 400);
            assert_eq!(initialized.get(), 2);
            assert_eq!(scheduled.get(), 1);
            assert_eq!(read(&service.resolve(&id).unwrap()), before);
            reject.set(false);
            assert_eq!(serve(creation("")).status, 202);
            assert!(service.resolve(&id).is_none());
            assert_eq!(serve(request(http::Method::Get, &id, "", "")).status, 404);
            assert!(matches!(
                client.submit(&token(&client), r#"{"finish":false}"#),
                Err(ClientError::NoPending)
            ));
        }

        #[test]
        fn history_is_atomic() {
            let service = FlowService::new();
            let id = service.register(history_scope(false)).unwrap();
            let client = service.resolve(&id).unwrap();
            client.run().unwrap();
            let initial = read(&client);
            let root: ScopeId = serde_json::from_value(initial["history"]["active_revision_id"].clone()).unwrap();
            assert_eq!(initial["history"]["revisions"][0]["data"]["count"], 0);
            assert!(!initial.to_string().contains("private"));
            client.run().unwrap();
            assert_eq!(read(&client), initial);
            answer(&client, false);
            let child = read(&client)["history"]["active_revision_id"].clone();
            client.restore(&root).unwrap();
            assert!(read(&client)["input"].is_null());
            client.run().unwrap();
            assert_eq!(count(&client), "0");
            assert_eq!(read(&client)["history"]["revisions"].as_array().unwrap().len(), 2);
            assert_ne!(token(&client), initial["input"]["request_id"]);
            answer(&client, false);
            let history = read(&client)["history"].clone();
            assert_eq!(history["revisions"].as_array().unwrap().len(), 3);
            assert_eq!(history["revisions"][1]["parent_id"], json!(root));
            assert_eq!(history["revisions"][2]["parent_id"], json!(root));
            assert_ne!(history["active_revision_id"], child);
        }

        #[test]
        fn history_projection_failure() {
            let service = FlowService::new();
            let id = service.register(history_scope(true)).unwrap();
            let client = service.resolve(&id).unwrap();
            client.run().unwrap();
            let before = read(&client);
            client.submit(&token(&client), r#"{"finish":false}"#).unwrap();
            assert!(client.run().is_err());
            assert!(matches!(client.read(), Err(ClientError::Internal { .. })));
            {
                let execution = client.execution.lock();
                assert_eq!(execution.published.history.revisions.len(), 1);
                assert_eq!(execution.scope.as_ref().unwrap().checkpoint_ids().count(), 1);
                assert_eq!(
                    *execution.scope.as_ref().unwrap().state().get::<u64>("count").unwrap(),
                    1
                );
            }
            let restored = service.handle_http(
                request(
                    http::Method::Post,
                    &id,
                    "/restore",
                    &json!({
                        "revision_id": before["history"]["active_revision_id"]
                    })
                    .to_string(),
                ),
                |_| Ok(()),
            );
            assert_eq!(restored.status, 202);
            service.run_pending().unwrap();
            let after = read(&client);
            assert_eq!(after["status"], "awaiting_input");
            assert_eq!(after["view"], before["view"]);
            assert_eq!(after["history"], before["history"]);
            assert_ne!(after["input"]["request_id"], before["input"]["request_id"]);
        }

        #[test]
        fn restore_validation() {
            let service = FlowService::new();
            let id = service.register(history_scope(false)).unwrap();
            service.run_pending().unwrap();
            let client = service.resolve(&id).unwrap();
            let before = read(&client);
            // Cross-execution IDs are checked in hosting: the guest-test entropy stub always returns zero.
            for (body, status) in [(json!({"revision_id": "missing"}), 404), (json!({}), 400)] {
                let response = service
                    .handle_http(request(http::Method::Post, &id, "/restore", &body.to_string()), |_| {
                        panic!("invalid restore scheduled")
                    });
                assert_eq!(response.status, status);
                assert_eq!(read(&client), before);
            }
            client.submit(&token(&client), r#"{"finish":false}"#).unwrap();
            let response = service.handle_http(
                request(
                    http::Method::Post,
                    &id,
                    "/restore",
                    &json!({"revision_id": before["history"]["active_revision_id"]}).to_string(),
                ),
                |_| panic!("busy restore scheduled"),
            );
            assert_eq!(response.status, 409);
        }

        #[test]
        fn lifecycle_scheduling_failure() {
            let service = FlowService::new();
            let created = service.serve(
                creation(""),
                false,
                || Ok(history_scope(false)),
                |_| Err("unavailable".into()),
            );
            assert_eq!(created.status, 500);
            let client = service.clients.lock().values().next().unwrap().clone();
            assert_eq!(read(&client)["status"], "failed");
            service.run_pending().unwrap();
            assert_eq!(read(&client)["status"], "failed");

            let id = service.replace(history_scope(false)).unwrap();
            service.run_pending().unwrap();
            let client = service.resolve(&id).unwrap();
            let root = read(&client)["history"]["active_revision_id"].clone();
            let restore = || {
                request(
                    http::Method::Post,
                    &id,
                    "/restore",
                    &json!({"revision_id": root}).to_string(),
                )
            };
            assert_eq!(
                service.handle_http(restore(), |_| Err("unavailable".into())).status,
                500
            );
            assert_eq!(read(&client)["status"], "failed");
            assert!(read(&client)["input"].is_null());
            assert_eq!(service.handle_http(restore(), |_| Ok(())).status, 202);
            service.run_pending().unwrap();
            assert_eq!(read(&client)["status"], "awaiting_input");
            assert_eq!(read(&client)["history"]["revisions"].as_array().unwrap().len(), 1);
        }

        fn mounted_flow(child: Flow, mode: crate::TraceMode) -> Flow {
            Flow::builder("parent")
                .entry("child")
                .exit("done")
                .flow(
                    "child",
                    child,
                    crate::ExitTransitions::new().transition("done", "done").unwrap(),
                    mode,
                )
                .build()
                .unwrap()
        }

        #[test]
        fn completed_child_view() {
            for mode in [
                crate::TraceMode::Expanded,
                crate::TraceMode::Collapsed("Child finished".into()),
            ] {
                for custom in [false, true] {
                    let mut child = counter_flow(Arc::new(AtomicUsize::new(0)), false, false);
                    if custom {
                        child.view = Some(|scope| {
                            let ui = ViewSpec::builder();
                            Ok(ViewSpec::finish(
                                &ui,
                                ui.text(format!(
                                    "{}:{}",
                                    scope.state().get::<u64>("count").unwrap(),
                                    scope.trace().entries.len(),
                                )),
                            )?)
                        });
                    }
                    let service = FlowService::new();
                    let id = service.register(scope(mounted_flow(child, mode.clone()))).unwrap();
                    let client = service.resolve(&id).unwrap();
                    client.run().unwrap();
                    answer(&client, false);
                    let before_exit = client.checkpoint().unwrap();
                    answer(&client, true);
                    assert_eq!(read(&client)["status"], "completed");
                    assert_eq!(count(&client), if custom { "2:2" } else { "2" });
                    let completed = client.checkpoint().unwrap();
                    client.restore(&before_exit).unwrap();
                    client.run().unwrap();
                    assert_eq!(count(&client), if custom { "1:1" } else { "1" });
                    client.restore(&completed).unwrap();
                    client.run().unwrap();
                    assert_eq!(read(&client)["status"], "completed");
                    assert_eq!(count(&client), if custom { "2:2" } else { "2" });
                }
            }
        }

        fn producing_step() -> Produce {
            Produce(Counter {
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
                broken_view: false,
            })
        }

        fn produce_then_child(child: Flow) -> Flow {
            Flow::builder("parent")
                .entry("produce")
                .exit("done")
                .step("produce", producing_step())
                .flow(
                    "fail",
                    child,
                    crate::ExitTransitions::new().transition("done", "done").unwrap(),
                    crate::TraceMode::Expanded,
                )
                .build()
                .unwrap()
        }

        #[test]
        fn child_failure_keeps_parent_view() {
            let child = Flow::builder("failure")
                .entry("fail")
                .exit("done")
                .step("fail", Fails)
                .build()
                .unwrap();
            let service = FlowService::new();
            let id = service
                .register(scope(produce_then_child(mounted_flow(
                    child,
                    crate::TraceMode::Expanded,
                ))))
                .unwrap();
            let client = service.resolve(&id).unwrap();
            client.run().unwrap();
            answer(&client, false);
            assert_eq!(read(&client)["status"], "failed");
            assert_eq!(count(&client), "1");
        }

        #[test]
        fn child_commit_replaces_parent_view() {
            let child = Flow::builder("child")
                .entry("produce")
                .exit("done")
                .step("produce", producing_step())
                .step("fail", Fails)
                .build()
                .unwrap();
            let service = FlowService::new();
            let id = service
                .register(scope(produce_then_child(mounted_flow(
                    child,
                    crate::TraceMode::Expanded,
                ))))
                .unwrap();
            let client = service.resolve(&id).unwrap();
            client.run().unwrap();
            answer(&client, false);
            assert_eq!(count(&client), "1");
            answer(&client, false);
            assert_eq!(read(&client)["status"], "failed");
            assert_eq!(count(&client), "2");
        }

        #[test]
        fn parent_commit_replaces_child_view() {
            let flow = Flow::builder("parent")
                .entry("child")
                .exit("done")
                .flow(
                    "child",
                    counter_flow(Arc::new(AtomicUsize::new(0)), false, false),
                    crate::ExitTransitions::new().transition("done", "counter").unwrap(),
                    crate::TraceMode::Expanded,
                )
                .step(
                    "counter",
                    Counter {
                        calls: Arc::new(AtomicUsize::new(0)),
                        fail: false,
                        broken_view: false,
                    },
                )
                .build()
                .unwrap();
            let service = FlowService::new();
            let id = service.register(scope(flow)).unwrap();
            let client = service.resolve(&id).unwrap();
            client.run().unwrap();
            answer(&client, true);
            let checkpoint = client.checkpoint().unwrap();
            assert_eq!(count(&client), "1");
            answer(&client, false);
            assert_eq!(count(&client), "2");
            client.restore(&checkpoint).unwrap();
            client.run().unwrap();
            assert_eq!(count(&client), "1");
        }

        #[test]
        fn child_view_error_keeps_commit() {
            let service = FlowService::new();
            let child = counter_flow(Arc::new(AtomicUsize::new(0)), false, true);
            let id = service
                .register(scope(mounted_flow(child, crate::TraceMode::Expanded)))
                .unwrap();
            let client = service.resolve(&id).unwrap();
            client.run().unwrap();
            client.submit(&token(&client), r#"{"finish":true}"#).unwrap();
            assert!(matches!(client.run(), Err(ClientError::Internal { message }) if message.contains("count")));
            assert!(matches!(client.read(), Err(ClientError::Internal { .. })));
            let execution = client.execution.lock();
            let scope = execution.scope.as_ref().unwrap();
            assert!(scope.is_finished());
            assert_eq!(scope.state().get::<u64>("count"), Some(&1));
            assert_eq!(scope.trace().entries.len(), 1);
            assert_eq!(execution.published.view.spec["ui"]["data"]["content"]["c0"], "0");
        }
    }

    struct Counter {
        calls: Arc<AtomicUsize>,
        fail: bool,
        broken_view: bool,
    }

    impl Step for Counter {
        fn description(&self, _: bool) -> String {
            "Counter".into()
        }
        fn input(&self, _: &Scope) -> Option<InputSpec> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut builder = InputSpec::builder();
            let field = builder.field("finish", "Finish", false).toggle();
            let submit = builder.submit("Submit");
            let root = builder.ui().column(vec![field, submit]);
            Some(builder.finish(root).unwrap())
        }
        fn view(&self, scope: &Scope) -> Result<ViewSpec, FlowError> {
            let count = scope.state().get::<u64>("count").unwrap();
            if self.broken_view && *count > 0 {
                return Err(FlowError::Execution("count: cannot render value".into()));
            }
            let builder = ViewSpec::builder();
            Ok(ViewSpec::finish(&builder, builder.text(count.to_string()))?)
        }
        fn model_template(&self, _: &Scope) -> TemplateSpec {
            TemplateSpec::Skip(TurnProposal::Advance {
                next: None,
                updates: StateUpdates::default(),
            })
        }
        fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            let count = scope.state().get::<u64>("count").unwrap();
            if self.fail && *count == 1 {
                return Err(FlowError::Execution("intentional failure".into()));
            }
            let TurnProposal::Advance { next, updates } = proposal else {
                unreachable!()
            };
            updates.set("count".into(), Some(Box::new(count + 1)));
            *next = Some(
                if *scope.get::<bool>(StateNamespace::Input, "finish").unwrap() {
                    "done"
                } else {
                    "counter"
                }
                .into(),
            );
            Ok(TraceSummary::Summary("committed".into()))
        }
    }

    fn setup(fail: bool, broken_view: bool) -> (FlowService, FlowClientId, FlowClient, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let scope = scope(counter_flow(calls.clone(), fail, broken_view));
        let service = FlowService::new();
        let id = service.register(scope).unwrap();
        let client = service.resolve(&id).unwrap();
        client.run().unwrap();
        (service, id, client, calls)
    }

    fn counter_flow(calls: Arc<AtomicUsize>, fail: bool, broken_view: bool) -> Flow {
        Flow::builder("counter")
            .entry("counter")
            .exit("done")
            .step(
                "counter",
                Counter {
                    calls,
                    fail,
                    broken_view,
                },
            )
            .build()
            .unwrap()
    }

    fn scope(flow: Flow) -> Scope {
        Scope::new(
            Arc::new(flow),
            State::builder()
                .field("count", "Count", 0_u64)
                .field("secret", "Never selected", "private".to_owned())
                .build()
                .unwrap(),
            AutoCheckpointConfig::Disabled,
            None,
        )
    }

    fn read(client: &FlowClient) -> JsonValue {
        serde_json::to_value(client.read().unwrap()).unwrap()
    }
    fn token(client: &FlowClient) -> String {
        client.read().unwrap().input.unwrap().request_id
    }
    fn count(client: &FlowClient) -> JsonValue {
        read(client)["view"]["spec"]["ui"]["data"]["content"]["c0"].clone()
    }
    fn answer(client: &FlowClient, finish: bool) {
        client
            .submit(&token(client), &json!({"finish": finish}).to_string())
            .unwrap();
        client.run().unwrap();
    }

    #[test]
    fn retained_publication() {
        let (_, _, client, calls) = setup(false, false);
        let before = read(&client);
        for _ in 0..3 {
            assert_eq!(read(&client), before);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(!before.to_string().contains("private"));
        assert!(
            matches!(client.submit(&token(&client), r#"{"finish":42}"#), Err(ClientError::Invalid { fields }) if fields[0].path == "/finish")
        );
        assert_eq!(read(&client), before);
        let old = token(&client);
        client.submit(&old, r#"{"finish":false}"#).unwrap();
        assert_eq!(count(&client), "0");
        assert_eq!(read(&client)["status"], "processing");
        assert!(matches!(
            client.submit(&old, r#"{"finish":false}"#),
            Err(ClientError::NoPending)
        ));
        client.run().unwrap();
        assert_eq!(count(&client), "1");
        assert!(matches!(
            client.submit(&old, r#"{"finish":false}"#),
            Err(ClientError::Stale)
        ));
        assert_ne!(token(&client), old);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        answer(&client, true);
        assert_eq!(read(&client)["status"], "completed");
        assert!(read(&client)["input"].is_null());
        assert_eq!(count(&client), "2");
    }

    #[test]
    fn retry_after_failure() {
        let (_, _, client, calls) = setup(true, false);
        answer(&client, false);
        let before = read(&client);
        let old = token(&client);
        answer(&client, false);
        let after = read(&client);
        assert_eq!(after["status"], "failed");
        assert_eq!(after["view"], before["view"]);
        assert_eq!(after["error"], "intentional failure");
        assert_ne!(token(&client), old);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(matches!(
            client.submit(&old, r#"{"finish":false}"#),
            Err(ClientError::Stale)
        ));
    }

    #[test]
    fn restore_and_replace() {
        let (service, id, client, _) = setup(false, false);
        let checkpoint = client.checkpoint().unwrap();
        let old = token(&client);
        answer(&client, false);
        client.restore(&checkpoint).unwrap();
        assert!(matches!(
            client.submit(&old, r#"{"finish":false}"#),
            Err(ClientError::NoPending)
        ));
        client.run().unwrap();
        assert_eq!(count(&client), "0");
        assert_ne!(token(&client), old);
        service.remove(&id);
        assert!(service.resolve(&id).is_none());
        let replacement = service
            .register(scope(counter_flow(Arc::new(AtomicUsize::new(0)), false, false)))
            .unwrap();
        assert_ne!(replacement, id);
    }

    #[test]
    fn child_and_snapshot_views() {
        let calls = Arc::new(AtomicUsize::new(0));
        let flow = Flow::builder("parent")
            .entry("child")
            .exit("done")
            .flow(
                "child",
                counter_flow(calls, false, false),
                crate::ExitTransitions::new().transition("done", "done").unwrap(),
                crate::TraceMode::Expanded,
            )
            .build()
            .unwrap();
        let mut scope = scope(flow);
        scope.run_until_input().unwrap();
        let saved = scope.clone();
        scope.input_handle().submit_input(r#"{"finish":false}"#).unwrap();
        scope.run_until_input().unwrap();
        let doc = |scope: &Scope| serde_json::to_value(scope.view().unwrap()).unwrap();
        assert_eq!(doc(&saved)["ui"]["data"]["content"]["c0"], "0");
        assert_eq!(doc(&scope)["ui"]["data"]["content"]["c0"], "1");
        let service = FlowService::new();
        let id = service.register(scope).unwrap();
        let client = service.resolve(&id).unwrap();
        client.run().unwrap();
        assert_eq!(read(&client)["step"]["id"], "counter");
        assert_eq!(count(&client), "1");
    }

    #[test]
    fn projection_failure() {
        let (service, id, client, _) = setup(false, true);
        let checkpoint = client.checkpoint().unwrap();
        let before = read(&client);
        let old = token(&client);
        client.submit(&old, r#"{"finish":false}"#).unwrap();
        assert!(client.run().is_err());
        for _ in 0..2 {
            assert!(matches!(client.read(), Err(ClientError::Internal { message }) if message.contains("count")));
        }
        {
            let execution = client.execution.lock();
            assert_eq!(
                *execution.scope.as_ref().unwrap().state().get::<u64>("count").unwrap(),
                1
            );
            assert_eq!(execution.published.view.spec["ui"]["data"]["content"]["c0"], "0");
        }
        let restored = service.handle_http(
            request(
                http::Method::Post,
                &id,
                "/restore",
                &json!({"revision_id": checkpoint}).to_string(),
            ),
            |_| Ok(()),
        );
        assert_eq!(restored.status, 202);
        service.run_pending().unwrap();
        let after = read(&client);
        assert_eq!(after["status"], "awaiting_input");
        assert_eq!(after["view"], before["view"]);
        assert_ne!(after["input"]["request_id"], before["input"]["request_id"]);
        assert!(matches!(
            client.submit(&old, r#"{"finish":false}"#),
            Err(ClientError::Stale)
        ));
    }

    fn request(method: http::Method, id: &FlowClientId, operation: &str, body: &str) -> http::Request {
        http::Request {
            method,
            url: format!("http://example.test/api/flows/{}{operation}", id.0),
            headers: vec![],
            body: Some(body.as_bytes().to_vec()),
        }
    }

    #[test]
    fn http_contract() {
        let (service, id, client, _) = setup(false, false);
        let before = read(&client);
        let get = || request(http::Method::Get, &id, "", "");
        // A replacement resolver changes neither routing nor the wire contract.
        let response = handle_http(get(), |_| Some(client.clone()), |_| panic!("GET scheduled work"));
        assert_eq!(serde_json::from_slice::<JsonValue>(&response.body).unwrap(), before);
        let response = service.handle_http(
            request(http::Method::Get, &FlowClientId("missing".into()), "", ""),
            |_| panic!(),
        );
        assert_eq!(response.status, 404);
        for body in ["{", "{}", r#"{"request_id":"x","values":{},"extra":1}"#] {
            assert_eq!(
                service
                    .handle_http(request(http::Method::Post, &id, "/input", body), |_| panic!())
                    .status,
                400
            );
        }
        let duplicate = format!(
            r#"{{"request_id":"{}","values":{{"finish":false,"finish":true}}}}"#,
            token(&client)
        );
        assert_eq!(
            service
                .handle_http(request(http::Method::Post, &id, "/input", &duplicate), |_| panic!())
                .status,
            422
        );
        assert_eq!(read(&client), before);
        let body = json!({"request_id": token(&client), "values": {"finish": false}}).to_string();
        let mut scheduled = false;
        let response = service.handle_http(request(http::Method::Post, &id, "/input", &body), |actual| {
            assert_eq!(actual, id);
            scheduled = true;
            Ok(())
        });
        assert!(scheduled);
        assert_eq!(response.status, 202);
        assert_eq!(
            serde_json::from_slice::<JsonValue>(&response.body).unwrap(),
            json!({"result":"accepted"})
        );
        assert_eq!(count(&client), "0");
    }

    #[test]
    fn separate_surfaces() {
        let (_, _, client, _) = setup(false, false);
        let response = read(&client);
        let input = &response["input"]["a2ui"];
        let result = &response["view"]["a2ui"];
        assert_ne!(
            input[0]["createSurface"]["surfaceId"],
            result[0]["createSurface"]["surfaceId"]
        );
        let button = input[1]["updateComponents"]["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["component"] == "Button")
            .unwrap();
        assert_eq!(
            button["action"]["event"]["context"]["request_id"],
            response["input"]["request_id"]
        );
        assert!(!result.to_string().contains("Button"));
        assert!(!result.to_string().contains("finish"));
    }

    struct Fails;
    impl Step for Fails {
        fn description(&self, _: bool) -> String {
            "Later failure".into()
        }
        fn input(&self, _: &Scope) -> Option<InputSpec> {
            None
        }
        fn model_template(&self, _: &Scope) -> TemplateSpec {
            TemplateSpec::Skip(TurnProposal::Advance {
                next: None,
                updates: StateUpdates::default(),
            })
        }
        fn finalize(&self, _: &Scope, _: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            Err(FlowError::Execution("later failure".into()))
        }
    }

    struct Produce(Counter);
    impl Step for Produce {
        fn description(&self, concise: bool) -> String {
            self.0.description(concise)
        }
        fn input(&self, scope: &Scope) -> Option<InputSpec> {
            self.0.input(scope)
        }
        fn view(&self, scope: &Scope) -> Result<ViewSpec, FlowError> {
            self.0.view(scope)
        }
        fn model_template(&self, scope: &Scope) -> TemplateSpec {
            self.0.model_template(scope)
        }
        fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            let summary = self.0.finalize(scope, proposal)?;
            if let TurnProposal::Advance { next, .. } = proposal {
                *next = Some("fail".into());
            }
            Ok(summary)
        }
    }

    #[test]
    fn later_failure_keeps_commit() {
        let flow = Flow::builder("later")
            .entry("produce")
            .step(
                "produce",
                Produce(Counter {
                    calls: Arc::new(AtomicUsize::new(0)),
                    fail: false,
                    broken_view: false,
                }),
            )
            .step("fail", Fails)
            .build()
            .unwrap();
        let service = FlowService::new();
        let id = service.register(scope(flow)).unwrap();
        let client = service.resolve(&id).unwrap();
        client.run().unwrap();
        answer(&client, false);
        assert_eq!(read(&client)["status"], "failed");
        assert!(read(&client)["input"].is_null());
        assert_eq!(read(&client)["step"]["id"], "fail");
        assert_eq!(count(&client), "1");
        client.run().unwrap();
        assert_eq!(count(&client), "1");
    }

    #[derive(Clone, schemars::JsonSchema)]
    #[schemars(with = "bool")]
    struct CheckedFlag(Arc<AtomicUsize>);
    impl crate::Value for CheckedFlag {
        fn encode(&self) -> String {
            "false".into()
        }
        fn decode(&self, value: &str) -> Result<Box<dyn crate::Value>, String> {
            self.0.fetch_add(1, Ordering::Relaxed);
            if value != "true" {
                return Err("choose true".into());
            }
            Ok(Box::new(self.clone()))
        }
        fn clone_box(&self) -> Box<dyn crate::Value> {
            Box::new(self.clone())
        }
    }

    struct Custom(Arc<AtomicUsize>);
    impl Step for Custom {
        fn description(&self, _: bool) -> String {
            "Custom decoder".into()
        }
        fn input(&self, _: &Scope) -> Option<InputSpec> {
            let mut builder = InputSpec::builder();
            let field = builder
                .field("checked", "Checked", CheckedFlag(self.0.clone()))
                .toggle();
            Some(builder.finish(field).unwrap())
        }
        fn model_template(&self, scope: &Scope) -> TemplateSpec {
            assert!(scope.get::<CheckedFlag>(StateNamespace::Input, "checked").is_some());
            TemplateSpec::Skip(TurnProposal::Advance {
                next: None,
                updates: StateUpdates::default(),
            })
        }
        fn finalize(&self, _: &Scope, _: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            Ok(TraceSummary::Summary("decoded".into()))
        }
    }

    #[test]
    fn http_decodes_once() {
        let decodes = Arc::new(AtomicUsize::new(0));
        let service = FlowService::new();
        let id = service
            .register(scope(
                Flow::builder("custom")
                    .entry("custom")
                    .step("custom", Custom(decodes.clone()))
                    .build()
                    .unwrap(),
            ))
            .unwrap();
        let client = service.resolve(&id).unwrap();
        client.run().unwrap();
        let before = read(&client);
        for (value, status, count) in [(json!(42), 422, 0), (json!(false), 422, 1), (json!(true), 202, 2)] {
            let body = json!({"request_id": token(&client), "values":{"checked":value}}).to_string();
            let response = service.handle_http(request(http::Method::Post, &id, "/input", &body), |_| Ok(()));
            assert_eq!(response.status, status);
            assert_eq!(decodes.load(Ordering::Relaxed), count);
            if status == 422 {
                assert_eq!(read(&client), before);
                assert_eq!(
                    serde_json::from_slice::<JsonValue>(&response.body).unwrap()["fields"][0]["path"],
                    "/checked"
                );
            }
        }
        client.run().unwrap();
        assert_eq!(decodes.load(Ordering::Relaxed), 2);
        assert_eq!(read(&client)["status"], "completed");
    }

    #[test]
    fn coalesced_workers() {
        let service = FlowService::new();
        let ids = (0..2)
            .map(|_| {
                service
                    .register(scope(counter_flow(Arc::new(AtomicUsize::new(0)), false, false)))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        service.run_pending().unwrap();
        for id in &ids {
            let client = service.resolve(id).unwrap();
            client.submit(&token(&client), r#"{"finish":false}"#).unwrap();
        }
        service.run_pending().unwrap();
        for id in &ids {
            assert_eq!(count(&service.resolve(id).unwrap()), "1");
        }
    }

    #[test]
    fn scheduling_failure() {
        let (service, id, client, _) = setup(false, false);
        let old = token(&client);
        let body = json!({"request_id":old, "values":{"finish":false}}).to_string();
        let response = service.handle_http(request(http::Method::Post, &id, "/input", &body), |_| {
            Err("worker unavailable".into())
        });
        assert_eq!(response.status, 500);
        let after = read(&client);
        assert_eq!(after["status"], "failed");
        assert!(after["input"].is_null());
        assert!(after["error"].as_str().unwrap().contains("request accepted"));
        assert_eq!(count(&client), "0");
        assert!(matches!(
            client.submit(&old, r#"{"finish":false}"#),
            Err(ClientError::NoPending)
        ));
        let _: ReadResponse = serde_json::from_value(after).unwrap();
    }
}
