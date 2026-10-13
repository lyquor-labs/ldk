use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use lyquid_flow::{AutoCheckpointConfig, StateNamespace};
use lyquid_test::test;
use refinement_loop_flow::{CHOICE_STATE_FIELD, DECISION_STATE_FIELD, REFINEMENT_INPUT_FIELD};

use super::tests::enter_request;
use super::*;
use lyquid_flow::service::{ClientError, FlowClient, FlowClientId, FlowService, ReadResponse, Status};

// Keep production aggregation, parent mounting, and text steps; script only the model and choice.
struct Refine(Arc<AtomicUsize>);
impl Step for Refine {
    fn description(&self, _: bool) -> String {
        "Scripted refinement".into()
    }
    fn input(&self, _: &Scope) -> Option<InputSpec> {
        None
    }
    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        self.0.fetch_add(1, Ordering::Relaxed);
        let message = scope.state().get::<String>(REFINEMENT_INPUT_FIELD).unwrap();
        let mut decision = scope
            .state()
            .get::<DecisionState>(DECISION_STATE_FIELD)
            .unwrap()
            .clone();
        decision.goal.soft_preferences.push(message.clone());
        decision.question.prompt = format!("Next hint after {message}");
        if message == "none" {
            decision.ranking.candidate_ids.clear();
        }
        let mut updates = StateUpdates::default();
        updates.set(DECISION_STATE_FIELD.into(), Some(Box::new(decision)));
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some("choose".into()),
            updates,
        })
    }
    fn finalize(&self, scope: &Scope, _: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        if scope.state().get::<String>(REFINEMENT_INPUT_FIELD).unwrap() == "fail" {
            return Err(FlowError::Execution("scripted failure".into()));
        }
        Ok(TraceSummary::Summary("Refined".into()))
    }
}

struct Choose;
impl Step for Choose {
    fn description(&self, _: bool) -> String {
        "Choose".into()
    }
    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        let mut builder = InputSpec::builder();
        let choice = builder
            .field(CHOICE_STATE_FIELD, "Choose", String::new())
            .choices(
                refinement_config()
                    .choice_options()
                    .into_iter()
                    .filter(|choice| {
                        choice.id != FINISH_CHOICE ||
                            scope
                                .state()
                                .get::<DecisionState>(DECISION_STATE_FIELD)
                                .unwrap()
                                .ranking
                                .candidate_ids
                                .is_empty()
                    })
                    .map(|choice| (choice.id, choice.label)),
            )
            .select_one();
        Some(builder.finish(choice).unwrap())
    }
    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        let choice = scope.get::<String>(StateNamespace::Input, CHOICE_STATE_FIELD).unwrap();
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some(if choice == "refine" { "feedback" } else { choice }.into()),
            updates: StateUpdates::default(),
        })
    }
    fn finalize(&self, _: &Scope, _: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        Ok(TraceSummary::Summary("Chose".into()))
    }
}

fn fixture() -> (Scope, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let searches = Arc::new(AtomicUsize::new(0));
    let refinements = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&searches);
    let child = Flow::builder("scripted-refinement")
        .entry("refine")
        .exit(RESTART_CHOICE)
        .exit(FINISH_CHOICE)
        .step("refine", Refine(Arc::clone(&refinements)))
        .step("choose", Choose)
        .step(
            "feedback",
            StepBuilder::new()
                .description("Collect a text message")
                .with_input(text_input(REFINEMENT_INPUT_FIELD, "Feedback"))
                .update_from(
                    REFINEMENT_INPUT_FIELD,
                    ValueSource::Input {
                        name: REFINEMENT_INPUT_FIELD.into(),
                    },
                )
                .next("refine")
                .summary("Received a text message")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let flow = build_flow(
        AggregateCandidatesStep {
            search: move |_: &SearchContext, round| {
                counted.fetch_add(1, Ordering::Relaxed);
                Ok(ProductCatalog {
                    products: vec![crate::Product {
                        id: format!("product-{round}"),
                        title: format!("Product {round}"),
                        source_url: format!("https://maker.example/{round}"),
                        source: "Fixture".into(),
                        price: None,
                        summary: "Test product".into(),
                        attributes: vec![],
                    }],
                    ..ProductCatalog::default()
                })
            },
        },
        child,
        restart_feedback_step(),
    );
    let mut scope = Scope::new(
        Arc::new(flow),
        initial_state().unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    enter_request(&mut scope, "Travel gear");
    (scope, searches, refinements)
}

struct Search {
    clients: FlowService,
    id: FlowClientId,
    client: FlowClient,
}

impl Search {
    fn start(scope: Scope) -> Self {
        let clients = FlowService::new();
        let id = clients.register(scope).unwrap();
        let client = clients.resolve(&id).unwrap();
        let mut search = Self { clients, id, client };
        search.run();
        search
    }
    fn read(&self) -> ReadResponse {
        self.client.read().unwrap()
    }
    fn result(&self) -> view::ShoppingResult {
        serde_json::from_value(self.read().view.spec["ui"]["data"]["shopping"].clone()).unwrap()
    }
    fn run(&mut self) {
        self.client.run().unwrap();
    }
    fn post(&self, request_id: &str, values: serde_json::Value) -> lyquid::http::Response {
        self.clients.handle_http(
            lyquid::http::Request {
                method: lyquid::http::Method::Post,
                url: format!("/api/flows/{}/input", self.id.0),
                headers: vec![],
                body: Some(
                    serde_json::to_vec(&serde_json::json!({"request_id": request_id, "values": values})).unwrap(),
                ),
            },
            |_| Ok(()),
        )
    }
    fn send(&mut self, field: &str, value: &str) {
        let token = self.read().input.unwrap().request_id;
        assert_eq!(self.post(&token, serde_json::json!({field: value})).status, 202);
        assert!(matches!(self.read().status, Status::Processing));
        self.run();
    }
    fn feedback(&mut self, choice: &str, message: &str) {
        self.send(CHOICE_STATE_FIELD, choice);
        self.send(
            if choice == RESTART_CHOICE {
                RESTART_FEEDBACK_FIELD
            } else {
                REFINEMENT_INPUT_FIELD
            },
            message,
        );
    }
    fn restore(&mut self, id: &lyquid_flow::ScopeId) {
        let response = self.clients.handle_http(
            lyquid::http::Request {
                method: lyquid::http::Method::Post,
                url: format!("/api/flows/{}/restore", self.id.0),
                headers: vec![],
                body: Some(serde_json::to_vec(&serde_json::json!({"revision_id": id})).unwrap()),
            },
            |_| Ok(()),
        );
        assert_eq!(response.status, 202);
        assert!(self.read().input.is_none());
        self.run();
    }
    fn checkpoint(&self) -> lyquid_flow::ScopeId {
        self.read().history.active_revision_id.unwrap()
    }
}

#[test]
fn history_branches() {
    let (scope, searches, refinements) = fixture();
    let mut search = Search::start(scope);
    let root = search.checkpoint();
    let old_request = search.read().input.unwrap().request_id;
    search.feedback("refine", "lightweight");
    let light = search.checkpoint();
    search.restore(&root);
    assert_eq!(
        search
            .post(&old_request, serde_json::json!({CHOICE_STATE_FIELD: "refine"}))
            .status,
        409
    );
    search.feedback("refine", "inexpensive");
    let cheap = search.checkpoint();
    assert_ne!(light.0, cheap.0);
    assert_eq!(search.read().history.revisions.len(), 3);
    assert!(
        search.read().history.revisions[1..]
            .iter()
            .all(|revision| revision.parent_id.as_ref() == Some(&root))
    );
    assert!(!search.result().soft_preferences.contains(&"lightweight".into()));
    search.restore(&light);
    assert!(search.result().soft_preferences.contains(&"lightweight".into()));
    assert!(!search.result().soft_preferences.contains(&"inexpensive".into()));
    search.restore(&cheap);
    assert!(search.result().soft_preferences.contains(&"inexpensive".into()));
    assert_eq!(searches.load(Ordering::Relaxed), 1);
    assert_eq!(refinements.load(Ordering::Relaxed), 3);
}

#[test]
fn search_restore() {
    let (scope, searches, refinements) = fixture();
    let mut search = Search::start(scope);
    let root = search.checkpoint();
    search.feedback(RESTART_CHOICE, "More compact products");
    let replacement = search.checkpoint();
    assert_eq!(search.result().candidates[0].id, "product-2");
    assert_eq!(search.read().history.revisions[1].data["kind"], "search");
    search.restore(&root);
    assert_eq!(search.result().candidates[0].source_url, "https://maker.example/1");
    assert!(search.result().restart_feedback.is_empty());
    search.restore(&replacement);
    assert_eq!(search.result().restart_feedback, ["More compact products"]);
    assert_eq!(searches.load(Ordering::Relaxed), 2);
    assert_eq!(refinements.load(Ordering::Relaxed), 2);
    search.feedback("refine", "none");
    search.send(CHOICE_STATE_FIELD, FINISH_CHOICE);
    assert!(matches!(search.read().status, Status::Completed));
    assert!(search.read().input.is_none());
    assert!(search.result().candidates.is_empty());
    search.restore(&root);
    assert!(matches!(search.read().status, Status::AwaitingInput));
    assert_eq!(search.result().candidates.len(), 1);
}

#[test]
fn failure_restore() {
    let (scope, _, refinements) = fixture();
    let mut search = Search::start(scope);
    let root = search.checkpoint();
    search.feedback("refine", "fail");
    assert!(matches!(search.read().status, Status::Failed));
    assert!(search.read().error.unwrap().contains("scripted failure"));
    assert_eq!(search.read().history.revisions.len(), 1);
    // The text Step committed before the model failed; retry starts from a saved choice checkpoint.
    search.restore(&root);
    assert!(search.read().error.is_none());
    search.feedback("refine", "retry");
    assert_eq!(search.read().history.revisions.len(), 2);
    assert!(!search.result().soft_preferences.contains(&"fail".into()));
    assert!(search.result().soft_preferences.contains(&"retry".into()));
    assert_eq!(refinements.load(Ordering::Relaxed), 3);
}

#[test]
fn input_contract() {
    let (scope, _, _) = fixture();
    let mut search = Search::start(scope);
    let root = search.checkpoint();
    let token = search.read().input.unwrap().request_id;
    // Finish is rejected by the retained InputSpec, not an application HTTP special case.
    assert_eq!(
        search
            .post(&token, serde_json::json!({CHOICE_STATE_FIELD: "finish"}))
            .status,
        422
    );
    assert_eq!(
        search.post(&token, serde_json::json!({CHOICE_STATE_FIELD: 42})).status,
        422
    );
    assert_eq!(search.read().input.unwrap().request_id, token);
    assert_eq!(
        search
            .post(&token, serde_json::json!({CHOICE_STATE_FIELD: "refine"}))
            .status,
        202
    );
    assert_eq!(
        search
            .post(&token, serde_json::json!({CHOICE_STATE_FIELD: "refine"}))
            .status,
        409
    );
    assert!(matches!(search.client.restore(&root), Err(ClientError::NoPending)));
    search.run();
    assert_eq!(
        search
            .post(&token, serde_json::json!({CHOICE_STATE_FIELD: "refine"}))
            .status,
        409
    );
    let feedback_token = search.read().input.unwrap().request_id;
    assert_eq!(
        search
            .post(&feedback_token, serde_json::json!({REFINEMENT_INPUT_FIELD: " \n "}))
            .status,
        422
    );
    assert_eq!(search.read().history.revisions.len(), 1);
    search.restore(&root);
}

#[test]
fn unknown_checkpoint() {
    let (scope, _, _) = fixture();
    let search = Search::start(scope);
    let root = search.checkpoint();
    assert!(search.client.restore(&"missing".into()).is_err());
    assert!(search.read().history.active_revision_id.as_ref() == Some(&root));
}

#[test]
fn replacement_retires_client() {
    let (scope, _, _) = fixture();
    let search = Search::start(scope);
    let (scope, _, _) = fixture();
    let replacement = search.clients.replace(scope).unwrap();
    assert!(search.clients.resolve(&search.id).is_none());
    assert_ne!(search.id.0, replacement.0);
    assert_eq!(search.post("old", serde_json::json!({})).status, 404);
}

#[test]
fn selected_view() {
    let (scope, _, _) = fixture();
    let mut search = Search::start(scope);
    let root = search.checkpoint();
    let view = search.read().view;
    assert!(view.spec.get("state").is_none());
    assert!(view.spec["ui"]["data"].get("shopping").is_some());
    assert_eq!(search.result().candidates[0].source_url, "https://maker.example/1");
    assert!(
        view.a2ui
            .iter()
            .any(|message| message.get("updateComponents").is_some())
    );
    search.feedback("refine", "none");
    assert!(search.result().candidates.is_empty());
    let mut publication = search.read();
    publication.history.revisions[0].data["soft_preferences"] = serde_json::json!(["Not in Scope"]);
    search.restore(&root);
    assert_eq!(search.result().request, "Travel gear");
    assert_eq!(search.result().candidates.len(), 1);
    assert!(!search.result().soft_preferences.contains(&"Not in Scope".into()));
}

#[test]
fn cooperative_child_input() {
    let (mut scope, _, _) = fixture();
    assert!(matches!(
        scope
            .input_handle()
            .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: "unexpected"}).to_string()),
        Err(FlowError::NoPendingInput)
    ));
    assert_eq!(scope.trace().entries.len(), 1);
    let (spec, child_state) = scope.run_until_input().unwrap().unwrap();
    assert!(spec.field_schema(CHOICE_STATE_FIELD).is_some());
    assert!(
        scope
            .state()
            .get::<DecisionState>(DECISION_STATE_FIELD)
            .unwrap()
            .goal
            .soft_preferences
            .is_empty()
    );
    assert!(
        !child_state
            .get::<DecisionState>(DECISION_STATE_FIELD)
            .unwrap()
            .goal
            .soft_preferences
            .is_empty()
    );
    let checkpoint = scope.checkpoint();
    assert!(
        scope
            .input_handle()
            .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: 42}).to_string())
            .is_err()
    );
    scope.restore(&checkpoint).unwrap();
    let (_, again) = scope.run_until_input().unwrap().unwrap();
    assert!(Arc::ptr_eq(&child_state, &again));
    let handle = scope.input_handle();
    assert!(handle.input_spec().is_some());
    assert!(Arc::ptr_eq(&again, &handle.state_snapshot().unwrap()));
}

#[test]
fn blocking_input_cancellation() {
    let child = Flow::builder("stopped-input")
        .entry("feedback")
        .exit("done")
        .step(
            "feedback",
            StepBuilder::new()
                .with_input_factory(|scope| {
                    // Stop after reaching input, so advance() exercises its waiting adapter.
                    scope.input_handle().request_stop();
                    text_input(REFINEMENT_INPUT_FIELD, "Feedback")
                })
                .update_from(
                    REFINEMENT_INPUT_FIELD,
                    ValueSource::Input {
                        name: REFINEMENT_INPUT_FIELD.into(),
                    },
                )
                .next("done")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let parent = Flow::builder("parent")
        .entry("child")
        .exit("done")
        .flow(
            "child",
            child,
            ExitTransitions::new().transition("done", "done").unwrap(),
            TraceMode::Expanded,
        )
        .build()
        .unwrap();
    let mut scope = Scope::new(
        Arc::new(parent),
        initial_state().unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    scope.set(
        StateNamespace::Default,
        REFINEMENT_INPUT_FIELD.into(),
        Some(Box::new("Staged parent message".to_owned())),
    );
    assert!(scope.advance().unwrap_err().to_string().contains("stopped"));
    assert_eq!(
        scope
            .get::<String>(StateNamespace::Default, REFINEMENT_INPUT_FIELD)
            .unwrap(),
        "Staged parent message"
    );
    assert_eq!(scope.current_step().0, "child");
    assert!(scope.trace().entries.is_empty());
    assert!(scope.input_handle().input_spec().is_none());
    assert!(scope.input_handle().state_snapshot().is_none());
}

#[test]
fn checkpoint_publication() {
    let (scope, _, _) = fixture();
    let mut search = Search::start(scope);
    let root = search.checkpoint();
    assert!(search.read().input.is_some());
    search.run();
    assert_eq!(search.read().history.revisions.len(), 1);
    search.send(CHOICE_STATE_FIELD, "refine");
    assert_eq!(search.read().history.revisions.len(), 1);
    search.restore(&root);
    search.run();
    assert_eq!(search.read().history.revisions.len(), 1);
}

#[test]
fn retained_nested_wait() {
    let (mut scope, searches, refinements) = fixture();
    let (_, original) = scope.run_until_input().unwrap().unwrap();
    let checkpoint = scope.checkpoint();
    scope
        .input_handle()
        .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: "refine"}).to_string())
        .unwrap();
    let (spec, snapshot) = scope.run_until_input().unwrap().unwrap();
    let (again, same_state) = scope.run_until_input().unwrap().unwrap();
    assert!(spec.field_schema(REFINEMENT_INPUT_FIELD).is_some());
    assert!(again.field_schema(REFINEMENT_INPUT_FIELD).is_some());
    assert!(Arc::ptr_eq(&snapshot, &same_state));
    assert_eq!(searches.load(Ordering::Relaxed), 1);
    assert_eq!(refinements.load(Ordering::Relaxed), 1);

    scope.restore(&checkpoint).unwrap();
    let (spec, restored) = scope.run_until_input().unwrap().unwrap();
    assert!(spec.field_schema(CHOICE_STATE_FIELD).is_some());
    assert!(Arc::ptr_eq(&restored, &original));
    assert_eq!(refinements.load(Ordering::Relaxed), 1);
}

#[test]
fn shared_nested_cursor() {
    let (mut scope, searches, refinements) = fixture();
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, REFINE_CANDIDATES_STEP);
    assert_eq!(scope.trace().entries.len(), 2);
    assert_eq!(searches.load(Ordering::Relaxed), 1);
    assert_eq!(refinements.load(Ordering::Relaxed), 0);

    let (spec, _) = scope.run_until_input().unwrap().unwrap();
    assert!(spec.field_schema(CHOICE_STATE_FIELD).is_some());
    assert_eq!(refinements.load(Ordering::Relaxed), 1);
    scope
        .input_handle()
        .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: "refine"}).to_string())
        .unwrap();
    scope.run_until_input().unwrap();
    scope
        .input_handle()
        .submit_input(&serde_json::json!({REFINEMENT_INPUT_FIELD: "none"}).to_string())
        .unwrap();
    scope.run_until_input().unwrap();
    scope
        .input_handle()
        .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: FINISH_CHOICE}).to_string())
        .unwrap();
    assert!(scope.run_until_input().unwrap().is_none());
    assert_eq!(scope.current_step().0, FINISHED_EXIT);
    assert_eq!(scope.trace().entries.len(), 3);
    scope.advance().unwrap();
    assert!(scope.run_until_input().unwrap().is_none());
    assert!(
        scope
            .input_handle()
            .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: FINISH_CHOICE}).to_string())
            .is_err()
    );
    assert_eq!(scope.trace().entries.len(), 3);
    assert_eq!(searches.load(Ordering::Relaxed), 1);
    assert_eq!(refinements.load(Ordering::Relaxed), 2);
}
