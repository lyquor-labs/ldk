use lyquid_flow::{
    ExitTransitions, Flow, FlowError, InputSpec, Scope, State, StateUpdates, Step, TemplateSpec, TraceMode,
    TraceSummary, TurnProposal,
};
use refinement_loop_flow::{CandidateRanking, DecisionRequest, DecisionState, ExitChoice, RefinementLoopConfig};
use text_input_step::TextInputStep;

use crate::{ProductCatalog, SearchContext, ShoppingRequest, ShoppingSearchState};

pub const SHOPPING_REQUEST_STATE_FIELD: &str = "shopping_request";
pub const CATALOG_STATE_FIELD: &str = "shopping_catalog";
pub const SHOPPING_SEARCH_STATE_FIELD: &str = "shopping_search_state";

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
        ExitChoice::new(FINISH_CHOICE, "Finish"),
    ])
    .expect("the shopping exit choices must be valid")
}

/// Builds the shopping Flow with application-owned retrieval and the reusable refinement child Flow.
pub fn flow(search: impl Fn(&SearchContext, u64) -> Result<ProductCatalog, String> + Send + Sync + 'static) -> Flow {
    build_flow(
        AggregateCandidatesStep { search },
        refinement_config().flow(),
        restart_feedback_step(),
    )
}

fn restart_feedback_step() -> TextInputStep {
    TextInputStep::new(
        RESTART_FEEDBACK_FIELD,
        "What should change about the candidate set?",
        AGGREGATE_CANDIDATES_STEP,
    )
}

fn build_flow(aggregation: impl Step, refinement: Flow, feedback: impl Step) -> Flow {
    let refinement_exits = ExitTransitions::new()
        .transition(RESTART_CHOICE, RESTART_FEEDBACK_STEP)
        .expect("the restart transition must be valid")
        .transition(FINISH_CHOICE, FINISHED_EXIT)
        .expect("the static refinement exit transition must be valid");
    Flow::builder("shopping-assistant")
        .description("Aggregate shopping candidates and guide the user through iterative refinement")
        .entry(AGGREGATE_CANDIDATES_STEP)
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
pub fn initial_state(request: ShoppingRequest) -> Result<State, String> {
    let decision_request = DecisionRequest::new(request.user_request.clone(), Vec::new());
    refinement_config()
        .add_state_fields(
            State::builder()
                .field(
                    SHOPPING_REQUEST_STATE_FIELD,
                    "Immutable shopping goal supplied by the application",
                    request,
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
            .get::<ShoppingRequest>(SHOPPING_REQUEST_STATE_FIELD)
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

        let TurnProposal::Advance { updates, .. } = proposal else {
            return Err(FlowError::Execution(
                "the deterministic aggregation Step requires an advance proposal".to_owned(),
            ));
        };
        let mut context =
            SearchContext::initial(aggregation_goal(&request.user_request, &[])).map_err(FlowError::Execution)?;
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

    #[test]
    fn aggregation_seeds_the_message_consumed_by_the_first_refinement_step() {
        let mut scope = Scope::new(
            Arc::new(flow(|_, _| Ok(ProductCatalog::default()))),
            initial_state(ShoppingRequest::new("Find a travel mug")).unwrap(),
            AutoCheckpointConfig::Disabled,
            None,
        );
        scope.advance().unwrap();
        let request = scope
            .state()
            .get::<DecisionRequest>(refinement_loop_flow::DECISION_REQUEST_STATE_FIELD)
            .unwrap();
        assert!(request.user_request.contains("Required shopping relevance:"));
        assert_eq!(
            scope
                .state()
                .get::<String>(refinement_loop_flow::REFINEMENT_INPUT_FIELD),
            Some(&request.user_request)
        );
        assert_eq!(scope.current_step().0, REFINE_CANDIDATES_STEP);
    }

    #[test]
    fn carries_restart_feedback_into_the_next_refinement_goal() {
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
    fn makes_requested_product_relevance_explicit() {
        let goal = aggregation_goal("I want coffee gear", &[]);

        assert!(goal.starts_with("Required shopping relevance:"));
        assert!(goal.contains("product must match the product type, category, or use case"));
        assert!(goal.contains("Preference wording within the request remains revisable"));
        assert!(goal.ends_with("User request: I want coffee gear"));
    }
}

#[cfg(test)]
#[path = "../tests/composition/mod.rs"]
mod composition_tests;

#[cfg(test)]
#[path = "../tests/history/mod.rs"]
mod history_tests;
