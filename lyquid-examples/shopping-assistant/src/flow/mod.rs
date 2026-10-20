mod view;

use lyquid_flow::{
    ExitTransitions, Flow, FlowError, InputSpec, Scope, State, StateUpdates, Step, TemplateSpec, TraceMode,
    TraceSummary, TurnProposal,
};
use lyquid_structured_step::{StructuredStepBuilder, ValueSource};
use refinement_loop_flow::{CandidateRanking, DecisionRequest, DecisionState, ExitChoice, RefinementLoopConfig};

use crate::{ProductCatalog, SearchContext, ShoppingSearchState};

pub const SHOPPING_REQUEST_STATE_FIELD: &str = "shopping_request";
pub const CATALOG_STATE_FIELD: &str = "shopping_catalog";
pub const SHOPPING_SEARCH_STATE_FIELD: &str = "shopping_search_state";

pub const SHOPPING_REQUEST_STEP: &str = "request";

pub const AGGREGATE_CANDIDATES_STEP: &str = "aggregate_candidates";
pub const REFINE_CANDIDATES_STEP: &str = "refine_candidates";
pub const RESTART_FEEDBACK_STEP: &str = "restart_feedback";
pub const RESTART_FEEDBACK_FIELD: &str = "shopping_restart_feedback";
pub const RESTART_CHOICE: &str = "restart";
pub const FINISH_CHOICE: &str = "finish";
pub const FINISHED_EXIT: &str = "finished";

/// The application owns exit IDs and labels; the LDK adds the continue-refining action.
pub fn refinement_config() -> RefinementLoopConfig {
    RefinementLoopConfig::new(vec![
        ExitChoice::new(RESTART_CHOICE, "New candidates"),
        ExitChoice::new(FINISH_CHOICE, "Finish with no matches"),
    ])
    .expect("the shopping exit choices must be valid")
    .nonblank()
    .with_available(|scope, choice| {
        choice.id != FINISH_CHOICE ||
            scope
                .state()
                .get::<DecisionState>(refinement_loop_flow::DECISION_STATE_FIELD)
                .expect("shopping decision")
                .ranking
                .candidate_ids
                .is_empty()
    })
}

/// Builds the shopping Flow with application-owned retrieval and the reusable refinement child Flow.
pub fn flow(search: impl Fn(&SearchContext, u64) -> Result<ProductCatalog, String> + Send + Sync + 'static) -> Flow {
    build_flow(
        AggregateCandidatesStep { search },
        refinement_config().flow(),
        restart_feedback_step(),
    )
}

fn text_input(field: &str, prompt: &str) -> InputSpec {
    let mut input = InputSpec::builder();
    let field = input.field(field, prompt, String::new()).non_blank().text_input();
    let submit = input.submit("Send");
    let layout = input.ui().column(vec![field, submit]);
    input.finish(layout).expect("valid shopping text input")
}

fn restart_feedback_step() -> impl Step {
    StructuredStepBuilder::new()
        .description("Collect a text message")
        .with_input(text_input(
            RESTART_FEEDBACK_FIELD,
            "What should change about the candidate set?",
        ))
        .update_from(
            RESTART_FEEDBACK_FIELD,
            ValueSource::Input {
                name: RESTART_FEEDBACK_FIELD.into(),
            },
        )
        .next(AGGREGATE_CANDIDATES_STEP)
        .summary("Received a text message")
        .build()
        .expect("valid shopping feedback wiring")
}

fn build_flow(aggregation: impl Step, refinement: Flow, feedback: impl Step) -> Flow {
    let refinement_exits = ExitTransitions::new()
        .transition(RESTART_CHOICE, RESTART_FEEDBACK_STEP)
        .expect("the restart transition must be valid")
        .transition(FINISH_CHOICE, FINISHED_EXIT)
        .expect("the static refinement exit transition must be valid");
    Flow::builder("shopping-assistant")
        .view(view::shopping_view)
        .history(view::shopping_history)
        .description("Aggregate shopping candidates and guide the user through iterative refinement")
        .entry(SHOPPING_REQUEST_STEP)
        .step(
            SHOPPING_REQUEST_STEP,
            StructuredStepBuilder::new()
                .description("Collect a text message")
                .with_input(text_input(
                    SHOPPING_REQUEST_STATE_FIELD,
                    "What are you looking for? Describe the product, budget, and your preferences.",
                ))
                .update_from(
                    SHOPPING_REQUEST_STATE_FIELD,
                    ValueSource::Input {
                        name: SHOPPING_REQUEST_STATE_FIELD.into(),
                    },
                )
                .next(AGGREGATE_CANDIDATES_STEP)
                .summary("Received a text message")
                .build()
                .expect("valid shopping request wiring"),
        )
        .exit(FINISHED_EXIT)
        .step(AGGREGATE_CANDIDATES_STEP, aggregation)
        .flow(
            REFINE_CANDIDATES_STEP,
            refinement,
            refinement_exits,
            TraceMode::Expanded,
        )
        .step(RESTART_FEEDBACK_STEP, feedback)
        .build()
        .expect("the static shopping-assistant Flow graph must be valid")
}

/// Creates the State for one shopping Scope before candidate retrieval.
pub fn initial_state() -> Result<State, String> {
    let decision_request = DecisionRequest::new("", Vec::new());
    refinement_config()
        .add_state_fields(
            State::builder()
                .field(
                    SHOPPING_REQUEST_STATE_FIELD,
                    "Shopping goal collected by the first input Step",
                    String::new(),
                )
                .field(
                    CATALOG_STATE_FIELD,
                    "Canonical products returned by candidate aggregation",
                    ProductCatalog::default(),
                )
                .field(
                    SHOPPING_SEARCH_STATE_FIELD,
                    "Parent-owned aggregation round and candidate restart feedback",
                    ShoppingSearchState::default(),
                )
                .field(
                    RESTART_FEEDBACK_FIELD,
                    "Feedback for the next aggregation round",
                    String::new(),
                ),
            decision_request,
        )?
        .build()
}

/// Returns the canonical aggregated catalog committed by the shopping Flow.
pub fn catalog(scope: &Scope) -> &ProductCatalog {
    scope
        .state()
        .get(CATALOG_STATE_FIELD)
        .expect("a shopping Scope must use shopping_assistant::initial_state")
}

struct AggregateCandidatesStep<S> {
    search: S,
}

impl<S> Step for AggregateCandidatesStep<S>
where
    S: Fn(&SearchContext, u64) -> Result<ProductCatalog, String> + Send + Sync + 'static,
{
    fn description(&self, concise: bool) -> String {
        if concise {
            "Search for 15-20 related products".to_owned()
        } else {
            "Retrieve source-backed shopping candidates before entering the refinement loop".to_owned()
        }
    }

    fn input(&self, _scope: &Scope) -> Option<InputSpec> {
        None
    }

    fn model_template(&self, _scope: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some(REFINE_CANDIDATES_STEP.into()),
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let request = scope
            .state()
            .get::<String>(SHOPPING_REQUEST_STATE_FIELD)
            .expect("the shopping State must be initialized");
        let mut search_state = scope
            .state()
            .get::<ShoppingSearchState>(SHOPPING_SEARCH_STATE_FIELD)
            .expect("the shopping State must include its search state")
            .clone();
        let feedback = scope
            .state()
            .get::<String>(RESTART_FEEDBACK_FIELD)
            .expect("the shopping State must include restart feedback")
            .trim();
        if !feedback.is_empty() {
            search_state.restart_feedback.push(feedback.to_owned());
        }
        let latest_restart_feedback = search_state.restart_feedback.last().cloned();
        search_state.aggregation_round = search_state
            .aggregation_round
            .checked_add(1)
            .ok_or_else(|| FlowError::Execution("shopping aggregation round sequence exhausted".to_owned()))?;

        let TurnProposal::Advance { next, updates } = proposal else {
            return Err(FlowError::Execution(
                "the deterministic aggregation Step requires an advance proposal".to_owned(),
            ));
        };
        let mut context = SearchContext::initial(aggregation_goal(request, &[])).map_err(FlowError::Execution)?;
        if !search_state.restart_feedback.is_empty() {
            let decision = scope
                .state()
                .get::<DecisionState>(refinement_loop_flow::DECISION_STATE_FIELD)
                .expect("the shopping State must include the decision");
            context = context.search_again(
                search_state.restart_feedback.join("\n"),
                decision.goal.clone(),
                catalog(scope).products.clone(),
            );
        }
        let catalog = (self.search)(&context, search_state.aggregation_round).map_err(FlowError::Execution)?;
        let decision_request = context.decision_request(&catalog);
        let candidate_ids = decision_request
            .candidates
            .iter()
            .map(|candidate| candidate.id.clone())
            .collect();
        let candidate_count = catalog.products.len();
        *next = Some(if candidate_count == 0 {
            RESTART_FEEDBACK_STEP.into()
        } else {
            REFINE_CANDIDATES_STEP.into()
        });
        updates.set(CATALOG_STATE_FIELD.to_owned(), Some(Box::new(catalog)));
        updates.set(
            SHOPPING_SEARCH_STATE_FIELD.to_owned(),
            Some(Box::new(search_state.clone())),
        );
        updates.set(
            refinement_loop_flow::REFINEMENT_INPUT_FIELD.to_owned(),
            Some(Box::new(decision_request.user_request.clone())),
        );
        updates.set(
            refinement_loop_flow::DECISION_REQUEST_STATE_FIELD.to_owned(),
            Some(Box::new(decision_request)),
        );
        updates.set(
            refinement_loop_flow::DECISION_STATE_FIELD.to_owned(),
            Some(Box::new(DecisionState {
                ranking: CandidateRanking { candidate_ids },
                ..DecisionState::default()
            })),
        );
        updates.set(
            refinement_loop_flow::CHOICE_STATE_FIELD.to_owned(),
            Some(Box::new(String::new())),
        );
        updates.set(RESTART_FEEDBACK_FIELD.to_owned(), Some(Box::new(String::new())));
        let suffix = latest_restart_feedback.as_ref().map_or(String::new(), |feedback| {
            format!(" using restart feedback {feedback:?}")
        });
        Ok(TraceSummary::Summary(format!(
            "Retrieved {candidate_count} shopping candidate(s) for round {}{suffix}",
            search_state.aggregation_round
        )))
    }
}

fn aggregation_goal(user_request: &str, restart_feedback: &[String]) -> String {
    let mut goal = format!(
        "Required shopping relevance:\nThe product must match the product type, category, or use case in the following request. Preference wording within the request remains revisable.\nUser request: {}",
        user_request.trim()
    );
    if restart_feedback.is_empty() {
        return goal;
    }
    let feedback = restart_feedback
        .iter()
        .map(|item| format!("- {item}"))
        .collect::<Vec<_>>()
        .join("\n");
    goal.push_str("\n\nCandidate-retrieval feedback from prior rounds:\n");
    goal.push_str(&feedback);
    goal
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lyquid_flow::AutoCheckpointConfig;
    use lyquid_test::test;

    use super::*;

    pub(super) fn enter_request(scope: &mut Scope, request: &str) {
        let (spec, _) = scope.run_until_input().unwrap().unwrap();
        assert!(spec.field_schema(SHOPPING_REQUEST_STATE_FIELD).is_some());
        scope
            .input_handle()
            .submit_input(&serde_json::json!({SHOPPING_REQUEST_STATE_FIELD: request}).to_string())
            .unwrap();
        scope.advance().unwrap();
        assert_eq!(scope.current_step().0, AGGREGATE_CANDIDATES_STEP);
    }

    #[test]
    fn initial_input() {
        use lyquid_flow::service::FlowService;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let searches = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&searches);
        let service = FlowService::new();
        let id = service
            .register(Scope::new(
                Arc::new(flow(move |context, _| {
                    assert!(context.original_request.contains("Find a travel mug"));
                    counted.fetch_add(1, Ordering::Relaxed);
                    Ok(ProductCatalog::default())
                })),
                initial_state().unwrap(),
                AutoCheckpointConfig::Disabled,
                None,
            ))
            .unwrap();
        service.run_pending().unwrap();
        let client = service.resolve(&id).unwrap();
        let first = client.read().unwrap();
        assert_eq!(first.step.id.0, SHOPPING_REQUEST_STEP);
        assert!(first.history.revisions.is_empty());
        assert_eq!(searches.load(Ordering::Relaxed), 0);
        let input = first.input.unwrap();
        for values in [
            serde_json::json!({}),
            serde_json::json!({SHOPPING_REQUEST_STATE_FIELD: "  "}),
            serde_json::json!({SHOPPING_REQUEST_STATE_FIELD: 3}),
        ] {
            assert!(client.submit(&input.request_id, &values.to_string()).is_err());
        }
        assert_eq!(client.read().unwrap().input.unwrap().request_id, input.request_id);
        client
            .submit(
                &input.request_id,
                &serde_json::json!({SHOPPING_REQUEST_STATE_FIELD: "Find a travel mug"}).to_string(),
            )
            .unwrap();
        service.run_pending().unwrap();
        assert_eq!(searches.load(Ordering::Relaxed), 1);
        let next = client.read().unwrap();
        assert!(
            next.input.unwrap().spec["schema"]["properties"]
                .get(RESTART_FEEDBACK_FIELD)
                .is_some()
        );
        assert!(next.history.revisions.is_empty());
        assert_eq!(next.view.spec["ui"]["data"]["shopping"]["request"], "Find a travel mug");
    }

    #[test]
    fn restart_goal() {
        let goal = aggregation_goal(
            "Find a travel mug",
            &[
                "The current products are too expensive".to_owned(),
                "Include glass options".to_owned(),
            ],
        );

        assert!(goal.contains("User request: Find a travel mug"));
        assert!(goal.contains("- The current products are too expensive"));
        assert!(goal.contains("- Include glass options"));
    }

    #[test]
    fn product_relevance() {
        let goal = aggregation_goal("I want coffee gear", &[]);

        assert!(goal.starts_with("Required shopping relevance:"));
        assert!(goal.contains("product must match the product type, category, or use case"));
        assert!(goal.contains("Preference wording within the request remains revisable"));
        assert!(goal.ends_with("User request: I want coffee gear"));
    }
}

#[cfg(test)]
#[path = "../../tests/composition/mod.rs"]
mod composition_tests;

#[cfg(test)]
#[path = "../../tests/history/mod.rs"]
mod history_tests;
