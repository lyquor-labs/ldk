use std::sync::Arc;

use lyquid_flow::{AutoCheckpointConfig, StateNamespace};
use lyquid_llm::ModelConfig;
use lyquid_test::test;
use refinement_loop_flow::{DECISION_REQUEST_STATE_FIELD, DECISION_STATE_FIELD, REFINEMENT_INPUT_FIELD};

use crate::flow::*;
use crate::*;

fn search_fixture(_: &SearchContext, round: u64) -> Result<ProductCatalog, String> {
    Ok(ProductCatalog {
        search_summary: "Gaming TVs from a scripted search".into(),
        retrieved_sources: vec!["https://maker.example/tvs".into()],
        products: (1..=20)
            .map(|index| Product {
                id: format!("product-{round}-{index}"),
                title: format!("Gaming TV {index}"),
                source_url: format!("https://maker.example/tv/{index}"),
                source: "Fixture maker".into(),
                price: None,
                summary: "TV for home gaming".into(),
                attributes: vec!["120 Hz".into()],
            })
            .collect(),
    })
}

// Script only the model/transport boundary, retaining the production parent graph and text finalizer.
struct ChildRound;
impl lyquid_flow::Step for ChildRound {
    fn description(&self, _: bool) -> String {
        "Script a candidate round".into()
    }
    fn input(&self, _: &lyquid_flow::Scope) -> Option<lyquid_flow::InputSpec> {
        None
    }
    fn model_template(&self, scope: &lyquid_flow::Scope) -> lyquid_flow::TemplateSpec {
        let round = scope
            .state()
            .get::<ShoppingSearchState>(SHOPPING_SEARCH_STATE_FIELD)
            .unwrap()
            .aggregation_round;
        let mut updates = lyquid_flow::StateUpdates::default();
        updates.set(
            DECISION_STATE_FIELD.to_owned(),
            Some(Box::new(refinement_loop_flow::DecisionState::default())),
        );
        lyquid_flow::TemplateSpec::Skip(lyquid_flow::TurnProposal::Advance {
            next: Some(if round == 1 { RESTART_CHOICE } else { FINISH_CHOICE }.into()),
            updates,
        })
    }
    fn finalize(
        &self, _: &lyquid_flow::Scope, _: &mut lyquid_flow::TurnProposal,
    ) -> Result<lyquid_flow::TraceSummary, lyquid_flow::FlowError> {
        Ok(lyquid_flow::TraceSummary::Summary("Candidate round".into()))
    }
}

struct Feedback;
impl lyquid_flow::Step for Feedback {
    fn description(&self, _: bool) -> String {
        "Script feedback transport".into()
    }
    fn input(&self, _: &lyquid_flow::Scope) -> Option<lyquid_flow::InputSpec> {
        None
    }
    fn model_template(&self, scope: &lyquid_flow::Scope) -> lyquid_flow::TemplateSpec {
        restart_feedback_step().model_template(scope)
    }
    fn finalize(
        &self, scope: &lyquid_flow::Scope, proposal: &mut lyquid_flow::TurnProposal,
    ) -> Result<lyquid_flow::TraceSummary, lyquid_flow::FlowError> {
        let mut received = scope.clone();
        received.set(
            StateNamespace::Input,
            RESTART_FEEDBACK_FIELD.to_owned(),
            Some(Box::new("  Include glass options  ".to_owned())),
        );
        restart_feedback_step().finalize(&received, proposal)
    }
}

#[test]
fn restart_collects_feedback_in_the_parent_and_reseeds_the_next_child() {
    let child = lyquid_flow::Flow::builder("scripted-model")
        .entry("round")
        .step("round", ChildRound)
        .exit(RESTART_CHOICE)
        .exit(FINISH_CHOICE)
        .build()
        .unwrap();
    let mut scope = lyquid_flow::Scope::new(
        Arc::new(build_flow(
            AggregateCandidatesStep { search: search_fixture },
            child,
            Feedback,
        )),
        initial_state(ShoppingRequest::new("Find a travel mug")).unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    scope.advance().unwrap(); // Aggregate canonical catalog.
    let catalog_before = catalog(&scope).clone();
    scope.advance().unwrap(); // Child exits to parent feedback, not directly to aggregation.
    assert_eq!(scope.current_step().0, RESTART_FEEDBACK_STEP);
    assert!(
        scope
            .state()
            .get::<ShoppingSearchState>(SHOPPING_SEARCH_STATE_FIELD)
            .unwrap()
            .restart_feedback
            .is_empty()
    );
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, AGGREGATE_CANDIDATES_STEP);
    scope.advance().unwrap();
    assert_eq!(catalog(&scope).products.len(), 20);
    assert_eq!(catalog(&scope).products[0].id, "product-2-1");
    assert_eq!(
        catalog(&scope).products[0].source_url,
        catalog_before.products[0].source_url
    );
    let search = scope
        .state()
        .get::<ShoppingSearchState>(SHOPPING_SEARCH_STATE_FIELD)
        .unwrap();
    assert_eq!(search.aggregation_round, 2);
    assert_eq!(search.restart_feedback, ["Include glass options"]);
    assert_eq!(scope.state().get::<String>(RESTART_FEEDBACK_FIELD).unwrap(), "");
    let request = scope
        .state()
        .get::<refinement_loop_flow::DecisionRequest>(DECISION_REQUEST_STATE_FIELD)
        .unwrap();
    assert!(request.user_request.contains("Include glass options"));
    assert_eq!(
        scope.state().get::<String>(REFINEMENT_INPUT_FIELD),
        Some(&request.user_request)
    );
    let decision = scope
        .state()
        .get::<refinement_loop_flow::DecisionState>(DECISION_STATE_FIELD)
        .unwrap();
    assert_eq!(decision.ranking.candidate_ids.len(), 20);
    assert!(decision.goal.hard_constraints.is_empty());
    scope.advance().unwrap();
    assert!(scope.is_finished());
    assert_eq!(scope.current_step().0, FINISHED_EXIT);
}

struct RejectModel;
impl lyquid_llm::Backend for RejectModel {
    fn prepare_request(
        &self, request: &lyquid_llm::ModelRequest,
    ) -> lyquid_llm::LlmResult<lyquid_llm::PreparedJsonApiRequest> {
        assert_eq!(request.model, "scripted");
        assert_eq!(request.max_output_tokens, Some(8192));
        assert!(request.prompt.contains("Required shopping relevance:"));
        assert!(request.prompt.contains("Find a travel mug"));
        assert_eq!(
            request.extra_body["text"]["format"]["schema"],
            refinement_config().model_turn_schema()
        );
        Err(lyquid_llm::LlmError::Backend {
            provider: "scripted".into(),
            message: "rejected for retry test".into(),
        })
    }
    fn parse_response(&self, _: lyquid_llm::JsonApiResponse) -> lyquid_llm::LlmResult<lyquid_llm::ModelResponse> {
        panic!("the rejected request must not reach the network")
    }
}

#[test]
fn production_mount_preserves_aggregation_and_goal_when_model_requests_fail() {
    let model = ModelConfig::new("scripted", RejectModel)
        .max_output_tokens(8192)
        .request_body_field(
            "text",
            serde_json::json!({"format": {"schema": refinement_config().model_turn_schema()}}),
        );
    let mut scope = lyquid_flow::Scope::new(
        Arc::new(flow(search_fixture)),
        initial_state(ShoppingRequest::new("Find a travel mug")).unwrap(),
        AutoCheckpointConfig::Disabled,
        Some(model),
    );
    scope.advance().unwrap();
    let request = scope
        .state()
        .get::<refinement_loop_flow::DecisionRequest>(DECISION_REQUEST_STATE_FIELD)
        .unwrap()
        .clone();
    for _ in 0..2 {
        assert!(
            scope
                .advance()
                .unwrap_err()
                .to_string()
                .contains("rejected for retry test")
        );
        assert_eq!(scope.current_step().0, REFINE_CANDIDATES_STEP);
        assert_eq!(scope.trace().entries.len(), 1);
        assert_eq!(
            scope
                .state()
                .get::<refinement_loop_flow::DecisionRequest>(DECISION_REQUEST_STATE_FIELD),
            Some(&request)
        );
        assert!(scope.input_handle().input_spec().is_none());
    }
}

#[test]
fn initial_tv_search_supplies_twenty_related_candidates_to_the_ldk_loop() {
    let mut scope = Scope::new(
        Arc::new(flow(|context, round| {
            let catalog = search_fixture(context, round)?;
            assert!(
                context
                    .decision_request(&catalog)
                    .user_request
                    .contains("TV for home gaming")
            );
            Ok(catalog)
        })),
        initial_state(ShoppingRequest::new("I want to get a TV for home gaming")).unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    scope.advance().unwrap();
    let request = scope
        .state()
        .get::<DecisionRequest>(DECISION_REQUEST_STATE_FIELD)
        .unwrap();
    assert_eq!(request.candidates.len(), 20);
    assert!(
        request
            .candidates
            .iter()
            .all(|candidate| candidate.description.contains("Gaming TV"))
    );
    assert_eq!(scope.current_step().0, REFINE_CANDIDATES_STEP);
    assert_eq!(catalog(&scope).products[0].source_url, "https://maker.example/tv/1");
}

#[test]
fn failed_search_does_not_commit_an_empty_catalog_or_advance_to_refinement() {
    let mut scope = Scope::new(
        Arc::new(flow(|_, _| Err("search provider unavailable".into()))),
        initial_state(ShoppingRequest::new("I want a TV")).unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    for _ in 0..2 {
        assert!(
            scope
                .advance()
                .unwrap_err()
                .to_string()
                .contains("search provider unavailable")
        );
        assert_eq!(scope.current_step().0, AGGREGATE_CANDIDATES_STEP);
        assert!(scope.trace().entries.is_empty());
        assert_eq!(
            scope
                .state()
                .get::<ShoppingSearchState>(SHOPPING_SEARCH_STATE_FIELD)
                .unwrap()
                .aggregation_round,
            0
        );
    }
}

#[test]
fn stop_request_prevents_a_mounted_loop_from_waiting_for_abandoned_input() {
    let config = refinement_config();
    let parent = lyquid_flow::Flow::builder("stopped-shopping")
        .entry("loop")
        .exit("done")
        .flow(
            "loop",
            config.flow(),
            lyquid_flow::ExitTransitions::new()
                .transition(RESTART_CHOICE, "done")
                .unwrap()
                .transition(FINISH_CHOICE, "done")
                .unwrap(),
            lyquid_flow::TraceMode::Expanded,
        )
        .build()
        .unwrap();
    let mut scope = lyquid_flow::Scope::new(
        Arc::new(parent),
        config
            .initial_state(refinement_loop_flow::DecisionRequest::new("No products", vec![]))
            .unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    let handle = scope.input_handle();
    assert!(handle.state_snapshot().is_none());
    // Dropping an observer must not stop an execution owned elsewhere.
    drop(handle.clone());
    assert!(handle.request_stop());
    assert!(!scope.input_handle().request_stop());
    assert!(scope.advance().unwrap_err().to_string().contains("stopped"));
    assert!(handle.input_spec().is_none());
    assert!(handle.state_snapshot().is_none());
    assert!(matches!(
        handle.submit_input(&serde_json::json!({refinement_loop_flow::CHOICE_STATE_FIELD: FINISH_CHOICE}).to_string()),
        Err(lyquid_flow::FlowError::NoPendingInput)
    ));
    assert!(scope.trace().entries.is_empty());
}
