use std::sync::{Arc, Mutex};

use crate::{
    Candidate, DECISION_REQUEST_STATE_FIELD, DECISION_STATE_FIELD, DecisionRequest, DecisionState,
    REFINEMENT_INPUT_FIELD, add_state_fields, refinement_step,
};
use lyquid_flow::{
    AutoCheckpointConfig, ExitTransitions, Flow, FlowError, InputSpec, Scope, State, StateUpdates, Step, TemplateSpec,
    TraceMode, TraceSummary, TurnProposal,
};
use lyquid_llm::{
    Backend, JsonApiResponse, LlmError, LlmResult, ModelConfig, ModelRequest, ModelResponse, PreparedJsonApiRequest,
};
use lyquid_test::test;
use serde_json::json;

// Supply a model proposal while exercising the configured finalizer and native child join.
struct ProposedDecision;

impl Step for ProposedDecision {
    fn description(&self, _: bool) -> String {
        "Scripted decision proposal".into()
    }
    fn input(&self, _: &Scope) -> Option<InputSpec> {
        None
    }
    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        assert!(matches!(
            refinement_step("result").model_template(scope),
            TemplateSpec::Template(_)
        ));
        let mut updates = StateUpdates::default();
        updates.set(DECISION_STATE_FIELD.into(), Some(Box::new(DecisionState::default())));
        TemplateSpec::Skip(TurnProposal::Advance { next: None, updates })
    }
    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        refinement_step("result").finalize(scope, proposal)
    }
}

#[test]
fn mounted_refinement_commits_an_empty_ranking_and_rejoins_the_parent() {
    let child = Flow::builder("refine-once")
        .entry("refine")
        .step("refine", ProposedDecision)
        .exit("result")
        .build()
        .unwrap();
    let parent = Flow::builder("parent")
        .entry("choose")
        .flow(
            "choose",
            child,
            ExitTransitions::new().transition("result", "done").unwrap(),
            TraceMode::Expanded,
        )
        .exit("done")
        .build()
        .unwrap();
    let state = add_state_fields(
        State::builder().field("parent", "Parent-owned data", 7_u64),
        DecisionRequest::new("Choose an option", vec![Candidate::new("a", "One option")]),
    )
    .unwrap()
    .build()
    .unwrap();
    let mut scope = Scope::new(Arc::new(parent), state, AutoCheckpointConfig::Disabled, None);

    scope.advance().unwrap();

    assert!(scope.is_finished());
    assert_eq!(scope.current_step().0, "done");
    assert_eq!(scope.state().get::<u64>("parent"), Some(&7));
    assert_eq!(
        scope.state().get::<DecisionState>(DECISION_STATE_FIELD),
        Some(&DecisionState::default())
    );
    assert!(scope.input_handle().input_spec().is_none());
    assert_eq!(scope.trace().entries.len(), 1);
    let TraceSummary::SubFlow(child_trace) = &scope.trace().entries[0].summary else {
        panic!("expanded composition should retain the child Trace");
    };
    assert_eq!(child_trace.entries.len(), 1);
}

struct CapturePrompt(Arc<Mutex<Vec<String>>>);

impl Backend for CapturePrompt {
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
        self.0.lock().unwrap().push(request.prompt.clone());
        Err(LlmError::Backend {
            provider: "fixture".into(),
            message: "captured without sending HTTP".into(),
        })
    }

    fn parse_response(&self, _: JsonApiResponse) -> LlmResult<ModelResponse> {
        unreachable!("the fixture never sends HTTP")
    }
}

#[test]
fn configured_data_reaches_the_model_literally_and_invalid_data_prevents_model_work() {
    for message in [json!("Prefer {{ literal_message }}"), json!(42)] {
        let request = DecisionRequest::new(
            "Choose {{ literal_request }}",
            vec![Candidate::new("a", "Facts {{ literal_candidate }}")],
        );
        let state = State::builder()
            .field(DECISION_REQUEST_STATE_FIELD, "Request", request)
            .field(DECISION_STATE_FIELD, "Decision", DecisionState::default())
            .field(REFINEMENT_INPUT_FIELD, "Message", message.clone())
            .build()
            .unwrap();
        let before = state.to_json().unwrap();
        let flow = Flow::builder("refine")
            .entry("refine")
            .step("refine", refinement_step("done"))
            .exit("done")
            .build()
            .unwrap();
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let mut scope = Scope::new(
            Arc::new(flow),
            state,
            AutoCheckpointConfig::Disabled,
            Some(ModelConfig::new("fixture", CapturePrompt(prompts.clone()))),
        );
        let error = scope.advance().unwrap_err();
        let captured = prompts.lock().unwrap();
        if message.is_string() {
            assert!(matches!(error, FlowError::Model(_)));
            assert_eq!(captured.len(), 1);
            for literal in ["literal_request", "literal_candidate", "literal_message"] {
                assert!(captured[0].contains(&format!("{{{{ {literal} }}}}")));
            }
        } else {
            assert!(error.to_string().contains("argument message"));
            assert!(captured.is_empty());
        }
        assert_eq!(scope.state().to_json().unwrap(), before);
        assert_eq!(scope.current_step().0, "refine");
        assert!(scope.trace().entries.is_empty());
    }
}

#[test]
fn invalid_refinement_state_fails_without_panicking_or_calling_the_model() {
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let flow = Flow::builder("missing-request")
        .entry("refine")
        .step("refine", refinement_step("done"))
        .exit("done")
        .build()
        .unwrap();
    let mut scope = Scope::new(
        Arc::new(flow),
        State::builder()
            .field(DECISION_STATE_FIELD, "Decision", DecisionState::default())
            .field(REFINEMENT_INPUT_FIELD, "Message", String::new())
            .build()
            .unwrap(),
        AutoCheckpointConfig::Disabled,
        Some(ModelConfig::new("fixture", CapturePrompt(prompts.clone()))),
    );
    assert!(
        scope
            .advance()
            .unwrap_err()
            .to_string()
            .contains(DECISION_REQUEST_STATE_FIELD)
    );
    assert!(prompts.lock().unwrap().is_empty());
    assert_eq!(scope.current_step().0, "refine");
    assert!(scope.trace().entries.is_empty());
}

#[test]
fn empty_candidate_input_is_rejected_before_model_work_or_commit() {
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let flow = Flow::builder("empty-request")
        .entry("refine")
        .step("refine", refinement_step("done"))
        .exit("done")
        .build()
        .unwrap();
    let state = crate::initial_state(DecisionRequest::new("Find an option", vec![])).unwrap();
    let before = state.to_json().unwrap();
    let mut scope = Scope::new(
        Arc::new(flow),
        state,
        AutoCheckpointConfig::Disabled,
        Some(ModelConfig::new("fixture", CapturePrompt(prompts.clone()))),
    );
    assert!(scope.advance().unwrap_err().to_string().contains("argument request"));
    assert!(prompts.lock().unwrap().is_empty());
    assert_eq!(scope.state().to_json().unwrap(), before);
    assert_eq!(scope.current_step().0, "refine");
    assert!(scope.trace().entries.is_empty());
}
