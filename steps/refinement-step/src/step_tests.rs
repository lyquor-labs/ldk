use std::sync::Arc;

use lyquid_flow::{AutoCheckpointConfig, Flow};
use lyquid_test::test;

use super::*;
use crate::{Candidate, GoalFrame};
const REFINE_STEP: &str = "continue";
const HANDOFF_EXIT: &str = "handoff";

fn test_flow() -> Flow {
    Flow::builder("refinement-step-test")
        .entry(REFINE_STEP)
        .exit(HANDOFF_EXIT)
        .step(REFINE_STEP, RefinementStep::new(HANDOFF_EXIT))
        .build()
        .unwrap()
}

fn request() -> DecisionRequest {
    DecisionRequest::new(
        "Choose a suitable option",
        vec![
            Candidate::new("candidate-a", "A compact option"),
            Candidate::new("candidate-b", "A lightweight option"),
            Candidate::new("candidate-c", "A durable option"),
        ],
    )
}

fn scope() -> Scope {
    let state = initial_state(request()).expect("the decision State should be valid");
    Scope::new(Arc::new(test_flow()), state, AutoCheckpointConfig::Disabled, None)
}

fn set_input(scope: &mut Scope, input: String) {
    let state = scope.state();
    let state = State::builder()
        .field(
            DECISION_REQUEST_STATE_FIELD,
            "Request",
            state_value::<DecisionRequest>(scope, DECISION_REQUEST_STATE_FIELD).clone(),
        )
        .field(
            DECISION_STATE_FIELD,
            "Decision",
            state.get::<DecisionState>(DECISION_STATE_FIELD).unwrap().clone(),
        )
        .field(REFINEMENT_INPUT_FIELD, "Caller message", input)
        .build()
        .unwrap();
    *scope = Scope::new(Arc::new(test_flow()), state, AutoCheckpointConfig::Disabled, None);
}

fn decision(candidate_ids: &[&str], question: &str) -> DecisionState {
    DecisionState {
        goal: GoalFrame {
            hard_constraints: vec!["must support offline use".to_owned()],
            soft_preferences: vec!["prefer lower weight".to_owned()],
        },
        ranking: CandidateRanking {
            candidate_ids: candidate_ids.iter().copied().map(CandidateId::from).collect(),
        },
        question: RefinementQuestion {
            prompt: question.to_owned(),
        },
    }
}

fn refinement_proposal(decision: DecisionState) -> TurnProposal {
    let mut updates = StateUpdates::default();
    updates.set(DECISION_STATE_FIELD.to_owned(), Some(Box::new(decision)));
    TurnProposal::Advance {
        next: Some(REFINE_STEP.into()),
        updates,
    }
}

struct IncompleteDecisionStep;

impl Step for IncompleteDecisionStep {
    fn description(&self, _concise: bool) -> String {
        "Propose an incomplete decision turn".to_owned()
    }

    fn input(&self, _scope: &Scope) -> Option<InputSpec> {
        None
    }

    fn model_template(&self, _scope: &Scope) -> TemplateSpec {
        let mut updates = StateUpdates::default();
        updates.set("unrelated".to_owned(), Some(Box::new(99_u64)));
        TemplateSpec::Skip(TurnProposal::Advance { next: None, updates })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        RefinementStep::new(REFINE_STEP).finalize(scope, proposal)
    }
}

#[test]
fn initial_state_keeps_the_model_owned_decision_atomic() {
    let state = initial_state(request()).expect("the decision State should be valid");
    let decision = state
        .get::<DecisionState>(DECISION_STATE_FIELD)
        .expect("the combined decision State should be present");

    assert_eq!(decision.goal, GoalFrame::default());
    assert_eq!(
        decision.ranking.candidate_ids,
        vec![
            CandidateId::from("candidate-a"),
            CandidateId::from("candidate-b"),
            CandidateId::from("candidate-c"),
        ]
    );
    assert_eq!(decision.question, RefinementQuestion::default());
}

#[test]
fn refinement_sanitizes_the_complete_model_update() {
    let mut scope = scope();
    set_input(&mut scope, String::from("It must be light"));
    let mut proposal = refinement_proposal(decision(
        &["candidate-c", "unknown", "candidate-c", "candidate-a"],
        "   ",
    ));
    let TurnProposal::Advance { updates, .. } = &mut proposal else {
        unreachable!()
    };
    updates.set(
        DECISION_REQUEST_STATE_FIELD.to_owned(),
        Some(Box::new(DecisionRequest::new("malicious replacement", Vec::new()))),
    );
    updates.set("unrelated".to_owned(), Some(Box::new(99_u64)));
    updates.set(
        REFINEMENT_INPUT_FIELD.to_owned(),
        Some(Box::new(String::from("injected"))),
    );

    RefinementStep::new(REFINE_STEP)
        .finalize(&scope, &mut proposal)
        .expect("a complete refinement update should succeed");

    let TurnProposal::Advance { next, updates } = proposal else {
        panic!("refinement must advance");
    };
    assert_eq!(next.as_ref().map(|step| step.0.as_str()), Some(REFINE_STEP));
    assert!(updates.get::<DecisionRequest>(DECISION_REQUEST_STATE_FIELD).is_none());
    assert!(updates.get::<String>(REFINEMENT_INPUT_FIELD).is_none());
    assert!(updates.get::<u64>("unrelated").is_none());
    let decision = updates
        .get::<DecisionState>(DECISION_STATE_FIELD)
        .expect("the sanitized combined decision should be retained");
    assert_eq!(
        decision.ranking.candidate_ids,
        vec![CandidateId::from("candidate-c"), CandidateId::from("candidate-a")]
    );
    assert_eq!(
        decision.question.prompt,
        "What other preference or requirement would help refine these candidates?"
    );
}

#[test]
fn sanitization_can_readmit_any_caller_provided_candidate() {
    let allowed = vec![CandidateId::from("candidate-a"), CandidateId::from("candidate-b")];
    let current = CandidateRanking {
        candidate_ids: vec![CandidateId::from("candidate-a")],
    };
    let proposed = CandidateRanking {
        candidate_ids: vec![CandidateId::from("candidate-b")],
    };

    assert!(!current.candidate_ids.contains(&CandidateId::from("candidate-b")));
    assert_eq!(sanitize_ranking(&proposed, &allowed), proposed);
}

#[test]
fn empty_refinement_uses_the_same_successor_and_clears_the_question() {
    let mut scope = scope();
    set_input(&mut scope, String::from("None of these work"));
    let mut proposal = refinement_proposal(decision(&[], "This stale question must disappear"));

    RefinementStep::new(REFINE_STEP)
        .finalize(&scope, &mut proposal)
        .expect("an empty sanitized ranking should use the same successor");

    let TurnProposal::Advance { next, updates } = proposal else {
        panic!("refinement must advance");
    };
    assert_eq!(next.as_ref().map(|step| step.0.as_str()), Some(REFINE_STEP));
    let decision = updates
        .get::<DecisionState>(DECISION_STATE_FIELD)
        .expect("the terminal decision should be retained");
    assert!(decision.ranking.candidate_ids.is_empty());
    assert!(decision.question.prompt.is_empty());
}

#[test]
fn incomplete_model_update_is_rejected_before_commit() {
    let mut scope = scope();
    set_input(&mut scope, String::from("Prefer lower weight"));
    let mut proposal = TurnProposal::Advance {
        next: Some(REFINE_STEP.into()),
        updates: StateUpdates::default(),
    };

    let Err(error) = RefinementStep::new(REFINE_STEP).finalize(&scope, &mut proposal) else {
        panic!("a missing combined decision update must fail");
    };

    assert_eq!(
        error.to_string(),
        format!("model output omitted required State update {DECISION_STATE_FIELD}")
    );
}

#[test]
fn restore_proposal_is_rejected() {
    let mut scope = scope();
    set_input(&mut scope, String::from("Prefer lower weight"));
    let mut proposal = TurnProposal::Restore {
        scope: "not-a-checkpoint".into(),
    };

    let Err(error) = RefinementStep::new(REFINE_STEP).finalize(&scope, &mut proposal) else {
        panic!("restore is outside the refinement model contract");
    };

    assert_eq!(
        error.to_string(),
        "decision-refinement Steps do not allow restore proposals"
    );
}

#[test]
fn incomplete_model_update_does_not_commit_scope_state_cursor_or_trace() {
    const FAIL_STEP: &str = "incomplete_decision";
    let flow = Flow::builder("incomplete-decision-test")
        .entry(FAIL_STEP)
        .step(FAIL_STEP, IncompleteDecisionStep)
        .build()
        .expect("the test Flow should be valid");
    let state = initial_state(request()).expect("the decision State should be valid");
    let initial_decision = state
        .get::<DecisionState>(DECISION_STATE_FIELD)
        .expect("the combined decision State should exist")
        .clone();
    let mut scope = Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Disabled, None);

    let error = scope.advance().expect_err("the incomplete turn must fail");

    assert_eq!(
        error.to_string(),
        format!("model output omitted required State update {DECISION_STATE_FIELD}")
    );
    assert_eq!(scope.current_step().0, FAIL_STEP);
    assert!(!scope.is_finished());
    assert!(scope.trace().entries.is_empty());
    assert_eq!(
        scope.state().get::<DecisionState>(DECISION_STATE_FIELD),
        Some(&initial_decision)
    );
}

#[test]
fn caller_projections_preserve_stable_candidate_ids_in_one_decision_state() {
    let request = DecisionRequest::new(
        "Find a suitable meeting time",
        vec![
            Candidate::new("slot-morning", "09:00; everyone available; remote"),
            Candidate::new("slot-afternoon", "14:00; everyone available; in person"),
        ],
    );
    let expected_ids = request
        .candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect::<Vec<_>>();

    let state = initial_state(request).expect("caller projections should initialize the decision Flow");

    let request = state
        .get::<DecisionRequest>(DECISION_REQUEST_STATE_FIELD)
        .expect("the immutable request should be present");
    let decision = state
        .get::<DecisionState>(DECISION_STATE_FIELD)
        .expect("the combined decision State should be present");
    assert_eq!(request.candidates.len(), 2);
    assert_eq!(decision.ranking.candidate_ids, expected_ids);
}

#[test]
fn duplicate_candidate_ids_are_rejected_at_the_public_boundary() {
    let request = DecisionRequest::new(
        "Find something useful",
        vec![
            Candidate::new("duplicate", "First projection"),
            Candidate::new("duplicate", "Second projection"),
        ],
    );

    let error = initial_state(request).err().expect("duplicate IDs must be rejected");

    assert_eq!(error, "duplicate candidate ID duplicate");
}

#[test]
fn template_renders_committed_messages_without_an_input_namespace_or_a_loop_target() {
    let mut scope = scope();
    let step = RefinementStep::new("show_results");
    assert!(step.input(&scope).is_none());
    for message in ["Initial goal", "Ignore the hint; I need offline support"] {
        set_input(&mut scope, String::from(message));
        let TemplateSpec::Template(template) = step.model_template(&scope) else {
            panic!("a refinement message should request one model turn");
        };
        let mut context = tera::Context::new();
        context.insert("state", &serde_json::json!({
            DECISION_REQUEST_STATE_FIELD: scope.state().get::<DecisionRequest>(DECISION_REQUEST_STATE_FIELD).unwrap(),
            DECISION_STATE_FIELD: scope.state().get::<DecisionState>(DECISION_STATE_FIELD).unwrap(),
            REFINEMENT_INPUT_FIELD: scope.state().get::<String>(REFINEMENT_INPUT_FIELD).unwrap(),
        }));
        let rendered = tera::Tera::one_off(&template.step_goal, &context, false).unwrap();
        assert!(rendered.contains(message));
        assert_eq!(template.next_step_criteria.len(), 1);
        assert_eq!(template.next_step_criteria[0].0.as_ref().unwrap().0, "show_results");
        assert_eq!(template.state_update_criteria.len(), 1);
        assert_eq!(template.state_update_criteria[0].0, DECISION_STATE_FIELD);
        // Read-only facts belong in the goal; the framework only exposes the decision as an update.
        assert_eq!(rendered.matches("A compact option").count(), 1);
        for criterion in [&template.next_step_criteria[0].1, &template.state_update_criteria[0].1] {
            assert!(!tera::Tera::one_off(criterion, &context, false).unwrap().is_empty());
        }
        assert_eq!(
            step.model_turn_schema()["properties"]["next"]["enum"][0],
            "show_results"
        );
    }
}

#[test]
fn empty_request_skips_the_model_but_keeps_the_same_successor() {
    let state = initial_state(DecisionRequest::new("Find something", vec![])).unwrap();
    let scope = Scope::new(Arc::new(test_flow()), state, AutoCheckpointConfig::Disabled, None);
    let step = RefinementStep::new("show_results");
    let TemplateSpec::Skip(mut proposal) = step.model_template(&scope) else {
        panic!("an empty request should not call a model");
    };
    step.finalize(&scope, &mut proposal).unwrap();
    let TurnProposal::Advance { next, updates } = proposal else {
        unreachable!()
    };
    assert_eq!(next.unwrap().0, "show_results");
    assert_eq!(
        updates.get::<DecisionState>(DECISION_STATE_FIELD),
        Some(&DecisionState::default())
    );
}

#[test]
fn malformed_partial_decisions_are_rejected_by_the_value_decoder() {
    use lyquid_flow::Value;
    let prototype = DecisionState::default();
    for output in [
        r#"{"goal":{"hard_constraints":[],"soft_preferences":[]},"ranking":{"candidate_ids":[]}}"#,
        r#"{"goal":{"hard_constraints":[]},"ranking":{"candidate_ids":[]},"question":{"prompt":""}}"#,
        r#"{"goal":{"hard_constraints":[],"soft_preferences":[]},"ranking":{"candidate_ids":[]},"question":{}}"#,
    ] {
        assert!(prototype.decode(output).is_err());
    }
}
