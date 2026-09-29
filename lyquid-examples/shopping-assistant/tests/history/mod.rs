use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use lyquid_flow::{AutoCheckpointConfig, StateNamespace};
use lyquid_test::test;
use refinement_loop_flow::{CHOICE_STATE_FIELD, DECISION_STATE_FIELD, REFINEMENT_INPUT_FIELD};

use super::*;
use crate::{ScopeView, publish_scope, reserve_input, restore_scope, run_scope, scope_view};

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
    fn input(&self, _: &Scope) -> Option<InputSpec> {
        let mut builder = InputSpec::builder();
        let choice = builder.field(CHOICE_STATE_FIELD, "Choose", String::new()).text_input();
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
            TextInputStep::new(REFINEMENT_INPUT_FIELD, "Feedback", "refine"),
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
    let scope = Scope::new(
        Arc::new(flow),
        initial_state(ShoppingRequest::new("Travel gear")).unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    (scope, searches, refinements)
}

fn start(scope: &mut Scope) -> ScopeView {
    let mut view = scope_view(scope.execution_id(), scope.state());
    run_scope(scope, &mut view, None);
    view
}

fn submit(scope: &mut Scope, view: &mut ScopeView, choice: &str, message: &str) {
    assert!(reserve_input(view, "choice"));
    run_scope(scope, view, Some(choice.into()));
    assert!(reserve_input(
        view,
        if choice == RESTART_CHOICE { "restart" } else { "refine" }
    ));
    run_scope(scope, view, Some(message.into()));
}

#[test]
fn history_uses_root_checkpoints_to_branch_and_restore_the_mounted_child_without_replay() {
    let (mut scope, searches, refinements) = fixture();
    let execution_id = scope.execution_id().clone();
    let mut view = start(&mut scope);
    let root = view.history.active_revision_id.clone().unwrap();
    let (_, original) = scope.run_until_input().unwrap().unwrap();
    submit(&mut scope, &mut view, "refine", "lightweight");
    let light = view.history.active_revision_id.clone().unwrap();
    assert_eq!(view.history.revisions.len(), 2);
    assert!(view.history.revisions[1].parent_id.as_ref() == Some(&root));
    restore_scope(&mut scope, &mut view, &root).unwrap();
    let (_, restored) = scope.run_until_input().unwrap().unwrap();
    assert!(Arc::ptr_eq(&restored, &original));
    assert_eq!(searches.load(Ordering::Relaxed), 1);
    assert_eq!(refinements.load(Ordering::Relaxed), 2);
    submit(&mut scope, &mut view, "refine", "inexpensive");
    let cheap = view.history.active_revision_id.clone().unwrap();
    assert_eq!(view.history.revisions.len(), 3);
    assert!(view.history.revisions[2].parent_id.as_ref() == Some(&root));
    assert_ne!(light.0, cheap.0);
    assert!(!view.soft_preferences.contains(&"lightweight".into()));
    restore_scope(&mut scope, &mut view, &light).unwrap();
    assert!(view.soft_preferences.contains(&"lightweight".into()));
    assert!(!view.soft_preferences.contains(&"inexpensive".into()));
    restore_scope(&mut scope, &mut view, &cheap).unwrap();
    assert!(view.soft_preferences.contains(&"inexpensive".into()));
    assert_eq!(refinements.load(Ordering::Relaxed), 3);
    restore_scope(&mut scope, &mut view, &root).unwrap();
    assert!(view.history.active_revision_id.as_ref() == Some(&root));
    assert!(view.history.revisions[0].parent_id.is_none());
    assert!(scope.execution_id() == &execution_id);
    assert!(view.scope_id == execution_id);
    assert_eq!(scope.checkpoint_ids().count(), 3);
}

#[test]
fn replacement_search_checkpoints_restore_catalog_feedback_and_trace_together() {
    let (mut scope, searches, refinements) = fixture();
    let mut view = start(&mut scope);
    let root = view.history.active_revision_id.clone().unwrap();
    submit(&mut scope, &mut view, RESTART_CHOICE, "More compact products");
    let replacement = view.history.active_revision_id.clone().unwrap();
    assert_eq!(view.candidates[0].id, "product-2");
    restore_scope(&mut scope, &mut view, &root).unwrap();
    assert_eq!(view.candidates[0].source_url, "https://maker.example/1");
    assert!(view.restart_feedback.is_empty());
    restore_scope(&mut scope, &mut view, &replacement).unwrap();
    assert_eq!(view.restart_feedback, ["More compact products"]);
    assert_eq!(searches.load(Ordering::Relaxed), 2);
    assert_eq!(refinements.load(Ordering::Relaxed), 2);
    // Resume a restored child and finish it: the restored parent Trace must not duplicate the search.
    submit(&mut scope, &mut view, "refine", "none");
    assert!(reserve_input(&mut view, "choice"));
    run_scope(&mut scope, &mut view, Some(FINISH_CHOICE.into()));
    assert_eq!(
        scope
            .trace()
            .entries
            .iter()
            .filter(|entry| entry.step.0 == AGGREGATE_CANDIDATES_STEP)
            .count(),
        2
    );
    assert!(scope.is_finished());
    assert_eq!(view.status, "no_match");
    restore_scope(&mut scope, &mut view, &root).unwrap();
    assert!(!scope.is_finished());
    assert_eq!(view.input_kind, Some("choice"));
}

#[test]
fn failed_refinement_does_not_replace_a_checkpoint_and_can_restore_for_retry() {
    let (mut scope, _, refinements) = fixture();
    let mut view = start(&mut scope);
    let root = view.history.active_revision_id.clone().unwrap();
    submit(&mut scope, &mut view, "refine", "fail");
    assert_eq!(view.status, "failed");
    assert!(view.error.as_ref().unwrap().contains("scripted failure"));
    assert_eq!(view.history.revisions.len(), 1);
    assert_eq!(scope.checkpoint_ids().count(), 1);
    assert!(!reserve_input(&mut view, "refine"));
    restore_scope(&mut scope, &mut view, &root).unwrap();
    assert!(view.error.is_none());
    submit(&mut scope, &mut view, "refine", "retry");
    assert_eq!(view.history.revisions.len(), 2);
    assert!(!view.soft_preferences.contains(&"fail".into()));
    assert!(view.soft_preferences.contains(&"retry".into()));
    assert_eq!(refinements.load(Ordering::Relaxed), 3);
}

#[test]
fn reserving_a_worker_rejects_duplicate_input_and_restore() {
    let (mut scope, _, _) = fixture();
    let mut view = start(&mut scope);
    let root = view.history.active_revision_id.clone().unwrap();
    assert!(!reserve_input(&mut view, "refine"));
    assert!(reserve_input(&mut view, "choice"));
    assert!(!reserve_input(&mut view, "choice"));
    assert!(restore_scope(&mut scope, &mut view, &root).is_err());
    run_scope(&mut scope, &mut view, Some("refine".into()));
    assert_eq!(view.history.revisions.len(), 1); // Choosing is not a completed revision.
    assert_eq!(scope.checkpoint_ids().count(), 1);
    restore_scope(&mut scope, &mut view, &root).unwrap();
}

#[test]
fn unknown_and_foreign_checkpoints_do_not_change_the_active_revision() {
    let (mut scope, _, _) = fixture();
    let (mut other, _, _) = fixture();
    let mut view = start(&mut scope);
    let mut other_view = start(&mut other);
    // Guest tests stub random_bytes with zeros; distinguish checkpoints by their sequence.
    submit(&mut other, &mut other_view, "refine", "other search");
    let original = view.history.active_revision_id.clone();
    assert!(restore_scope(&mut scope, &mut view, &"missing".into()).is_err());
    assert!(
        restore_scope(
            &mut scope,
            &mut view,
            other_view.history.active_revision_id.as_ref().unwrap()
        )
        .is_err()
    );
    assert!(view.history.active_revision_id == original);
}

#[test]
fn removing_a_scope_drops_idle_checkpoints_and_does_not_republish_a_late_worker_result() {
    use lyquid::prelude::new_hashmap;

    let (mut scope, _, _) = fixture();
    let view = start(&mut scope);
    let id = scope.execution_id().clone();
    let stop = scope.input_handle();
    let mut scopes = new_hashmap();
    let mut views = new_hashmap();
    scopes.insert(id.clone(), scope);
    views.insert(id.clone(), view);
    stop.request_stop();
    scopes.remove(&id);
    views.remove(&id);
    assert!(scopes.is_empty());
    assert!(views.is_empty());

    let (mut scope, searches, _) = fixture();
    let mut view = scope_view(scope.execution_id(), scope.state());
    scope.input_handle().request_stop();
    run_scope(&mut scope, &mut view, None);
    assert_eq!(view.status, "failed");
    publish_scope(&mut scopes, &mut views, scope, view);
    assert!(scopes.is_empty());
    assert!(views.is_empty());
    assert_eq!(searches.load(Ordering::Relaxed), 0);

    // Also discard a successful model result that completed just before replacement.
    let (mut scope, _, _) = fixture();
    let view = start(&mut scope);
    publish_scope(&mut scopes, &mut views, scope, view);
    assert!(scopes.is_empty());
    assert!(views.is_empty());
}

#[test]
fn publishing_a_scope_returns_ownership_and_a_coherent_display_view() {
    use lyquid::prelude::new_hashmap;

    let (mut scope, _, _) = fixture();
    let id = scope.execution_id().clone();
    let mut views = new_hashmap();
    views.insert(id.clone(), scope_view(&id, scope.state()));
    let mut scopes = new_hashmap();
    let view = start(&mut scope);
    publish_scope(&mut scopes, &mut views, scope, view);
    assert!(scopes.get(&id).unwrap().execution_id() == &id);
    let view = views.get(&id).unwrap();
    assert!(view.scope_id == id);
    assert_eq!(view.status, "awaiting_input");
    assert_eq!(view.input_kind, Some("choice"));
    assert_eq!(view.history.revisions[0].candidate_count, view.candidates.len());
}

#[test]
fn cooperative_scope_yields_child_state_and_validates_input_without_blocking() {
    let (mut scope, _, _) = fixture();
    assert!(matches!(
        scope
            .input_handle()
            .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: "unexpected"}).to_string()),
        Err(FlowError::NoPendingInput)
    ));
    assert!(scope.trace().entries.is_empty());
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
fn completed_round_waits_at_choose_without_entering_feedback_or_repeating_refinement() {
    let (mut scope, searches, refinements) = fixture();
    let mut view = start(&mut scope);
    assert_eq!(view.input_kind, Some("choice"));
    assert_eq!(view.history.revisions.len(), 1);
    let checkpoint = view.history.active_revision_id.clone().unwrap();
    let (_, original) = scope.run_until_input().unwrap().unwrap();

    assert!(reserve_input(&mut view, "choice"));
    run_scope(&mut scope, &mut view, Some("refine".into()));
    assert_eq!(view.input_kind, Some("refine"));
    assert_eq!(searches.load(Ordering::Relaxed), 1);
    assert_eq!(refinements.load(Ordering::Relaxed), 1);
    let (spec, snapshot) = scope.run_until_input().unwrap().unwrap();
    let (again, same_state) = scope.run_until_input().unwrap().unwrap();
    assert!(spec.field_schema(REFINEMENT_INPUT_FIELD).is_some());
    assert!(again.field_schema(REFINEMENT_INPUT_FIELD).is_some());
    assert!(Arc::ptr_eq(&snapshot, &same_state));
    assert_eq!(view.history.revisions.len(), 1);
    assert!(view.history.active_revision_id.as_ref() == Some(&checkpoint));

    restore_scope(&mut scope, &mut view, &checkpoint).unwrap();
    let (spec, restored) = scope.run_until_input().unwrap().unwrap();
    assert!(spec.field_schema(CHOICE_STATE_FIELD).is_some());
    assert_eq!(view.input_kind, Some("choice"));
    assert!(Arc::ptr_eq(&restored, &original));
    assert_eq!(refinements.load(Ordering::Relaxed), 1);
}

#[test]
fn stepwise_and_run_until_input_execution_share_the_same_nested_cursor() {
    let (mut scope, searches, refinements) = fixture();
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, REFINE_CANDIDATES_STEP);
    assert_eq!(scope.trace().entries.len(), 1);
    assert_eq!(searches.load(Ordering::Relaxed), 1);
    assert_eq!(refinements.load(Ordering::Relaxed), 0);

    let (spec, _) = scope.run_until_input().unwrap().unwrap();
    assert!(spec.field_schema(CHOICE_STATE_FIELD).is_some());
    assert_eq!(refinements.load(Ordering::Relaxed), 1);
    scope
        .input_handle()
        .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: FINISH_CHOICE}).to_string())
        .unwrap();
    assert!(scope.run_until_input().unwrap().is_none());
    assert_eq!(scope.current_step().0, FINISHED_EXIT);
    assert_eq!(scope.trace().entries.len(), 2);
    scope.advance().unwrap();
    assert!(scope.run_until_input().unwrap().is_none());
    assert!(
        scope
            .input_handle()
            .submit_input(&serde_json::json!({CHOICE_STATE_FIELD: FINISH_CHOICE}).to_string())
            .is_err()
    );
    assert_eq!(scope.trace().entries.len(), 2);
    assert_eq!(searches.load(Ordering::Relaxed), 1);
    assert_eq!(refinements.load(Ordering::Relaxed), 1);
}

#[test]
fn blocking_adapter_stops_when_a_nested_input_request_is_cancelled() {
    let child = Flow::builder("stopped-input")
        .entry("feedback")
        .exit("done")
        .step(
            "feedback",
            TextInputStep::new(REFINEMENT_INPUT_FIELD, "Feedback", "done").with_prompt(|scope| {
                // Stop after reaching input, so advance() exercises its waiting adapter.
                scope.input_handle().request_stop();
                "Feedback".into()
            }),
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
        initial_state(ShoppingRequest::new("Travel gear")).unwrap(),
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
fn history_api_uses_scope_execution_and_checkpoint_ids_without_a_session_id() {
    let (mut scope, _, _) = fixture();
    let view = start(&mut scope);
    let root = view.history.active_revision_id.as_ref().unwrap();
    let value = serde_json::to_value(&view).unwrap();
    assert_eq!(value["scope_id"], scope.execution_id().0);
    assert!(value.get("session_id").is_none());
    let history = value["history"].as_object().unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history["active_revision_id"], root.0);
    assert_eq!(history["revisions"].as_array().unwrap().len(), 1);
    assert_eq!(history["revisions"][0]["id"], root.0);
    let body: crate::RestoreBody = serde_json::from_value(serde_json::json!({
        "scope_id": scope.execution_id(),
        "revision_id": root,
    }))
    .unwrap();
    assert!(&body.scope_id == scope.execution_id());
    assert!(&body.revision_id == root);
    assert!(
        crate::query_scope_id(&format!("/api/scope?id={}", scope.execution_id())).as_ref() ==
            Some(scope.execution_id())
    );
    assert!(crate::query_scope_id("/api/scope?id=").is_none());
    assert!(crate::query_scope_id("/api/scope").is_none());
}

#[test]
fn restoring_reads_display_data_from_scope_not_history_metadata() {
    let (mut scope, _, _) = fixture();
    let mut view = start(&mut scope);
    let root = view.history.active_revision_id.clone().unwrap();
    submit(&mut scope, &mut view, "refine", "none");
    assert!(view.candidates.is_empty());
    assert_eq!(view.history.revisions.len(), 2);
    view.hard_constraints = vec!["Not in Scope".into()];
    view.request = "Not the real request".into();
    view.hint = "Not the real hint".into();
    restore_scope(&mut scope, &mut view, &root).unwrap();
    assert_eq!(view.request, "Travel gear");
    assert_eq!(view.candidates[0].id, "product-1");
    assert!(!view.hard_constraints.contains(&"Not in Scope".into()));
    assert_ne!(view.hint, "Not the real hint");
    assert_eq!(view.history.revisions.len(), 2);
    assert!(view.history.revisions[0].active);
    assert!(!view.history.revisions[1].active);
}
