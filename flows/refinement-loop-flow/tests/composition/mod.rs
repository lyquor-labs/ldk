use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::flow::{CHOICE_STEP, INPUT_STEP, REFINE_STEP, input_step};
use crate::*;
use lyquid_configured_step::{StepBuilder, ValueSource};
use lyquid_flow::{
    AutoCheckpointConfig, ExitTransitions, Flow, FlowError, InputSpec, Scope, State, StateNamespace, StateUpdates,
    Step, TemplateSpec, TraceMode, TraceSummary, TurnProposal,
};
use lyquid_test::test;

// Replace only input transport and model calls. Actual library finalizers, commits and child joins run unchanged.
struct Submitted {
    step: Arc<dyn Step>,
    field: &'static str,
    values: Vec<String>,
    index: AtomicUsize,
    feedback: Vec<String>,
}

impl Submitted {
    fn new(step: impl Step, field: &'static str, values: &[&str]) -> Self {
        Self {
            step: Arc::new(step),
            field,
            values: values.iter().map(|value| (*value).to_owned()).collect(),
            index: AtomicUsize::new(0),
            feedback: vec![],
        }
    }
}

impl Step for Submitted {
    fn description(&self, _: bool) -> String {
        "Scripted input transport".to_owned()
    }
    fn input(&self, _: &Scope) -> Option<InputSpec> {
        None
    }
    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        self.step.model_template(scope)
    }
    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let index = self.index.fetch_add(1, Ordering::SeqCst);
        let mut received = scope.clone();
        received.set(
            StateNamespace::Input,
            self.field.to_owned(),
            Some(Box::new(self.values.get(index).expect("unexpected input wait").clone())),
        );
        if self.field == CHOICE_STATE_FIELD && self.values[index] == CONTINUE_CHOICE {
            let feedback_index = self.values[..index].iter().filter(|id| *id == CONTINUE_CHOICE).count();
            received.set(
                StateNamespace::Input,
                REFINEMENT_INPUT_FIELD.into(),
                Some(Box::new(self.feedback[feedback_index].clone())),
            );
        }
        self.step.finalize(&received, proposal)
    }
}

struct ModelTurn<S> {
    step: S,
    attempts: AtomicUsize,
    reject_first: bool,
}
impl<S: Step> Step for ModelTurn<S> {
    fn description(&self, _: bool) -> String {
        "Scripted model response".to_owned()
    }
    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        self.step.input(scope)
    }
    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        assert!(
            scope
                .get::<String>(StateNamespace::Input, REFINEMENT_INPUT_FIELD)
                .is_none()
        );
        let message = scope.state().get::<String>(REFINEMENT_INPUT_FIELD).unwrap();
        let (color, hint) = match message.as_str() {
            "Blue is required" => ("blue", "What size?"),
            "Red is required instead" => {
                let previous = scope.state().get::<DecisionState>(DECISION_STATE_FIELD).unwrap();
                assert_eq!(previous.goal.hard_constraints, ["blue"]);
                assert_eq!(previous.ranking.candidate_ids, [CandidateId::from("blue")]);
                ("red", "Any other requirements?")
            }
            _ => ("", ""),
        };
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        let mut updates = StateUpdates::default();
        if !self.reject_first || attempt > 0 {
            updates.set(
                DECISION_STATE_FIELD.to_owned(),
                Some(Box::new(DecisionState {
                    goal: GoalFrame {
                        hard_constraints: vec![color.to_owned()],
                        soft_preferences: vec![],
                    },
                    ranking: CandidateRanking {
                        candidate_ids: if color.is_empty() { vec![] } else { vec![color.into()] },
                    },
                    question: RefinementQuestion {
                        prompt: hint.to_owned(),
                    },
                })),
            );
        }
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some("injected".into()),
            updates,
        })
    }
    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        self.step.finalize(scope, proposal)
    }
}

fn request(goal: &str) -> DecisionRequest {
    DecisionRequest::new(
        goal,
        vec![
            Candidate::new("blue", "Blue option"),
            Candidate::new("red", "Red option"),
        ],
    )
}

fn exit_config() -> RefinementLoopConfig {
    RefinementLoopConfig::new(vec![
        ExitChoice::new("compare", "Compare these options"),
        ExitChoice::new("restart", "Request different candidates"),
        ExitChoice::new("save", "Save for later"),
    ])
    .unwrap()
}

fn scripted_flow(
    config: &RefinementLoopConfig, entry: &str, messages: &[&str], choices: &[&str], reject_first: bool,
) -> Flow {
    let mut builder = Flow::builder("scripted-refinement-loop")
        .entry(entry)
        .step(
            INPUT_STEP,
            Submitted::new(input_step(false), REFINEMENT_INPUT_FIELD, messages),
        )
        .step(
            REFINE_STEP,
            ModelTurn {
                step: config.refinement_step(),
                attempts: AtomicUsize::new(0),
                reject_first,
            },
        );
    if let Some(choice_step) = config.choice_step() {
        for choice in config.choice_options().iter().skip(1) {
            builder = builder.exit(choice.id.as_str());
        }
        let mut submitted = Submitted::new(choice_step, CHOICE_STATE_FIELD, choices);
        let feedback = if entry == INPUT_STEP { &messages[1..] } else { messages };
        submitted.feedback = feedback.iter().map(|message| (*message).to_owned()).collect();
        builder = builder.step(CHOICE_STEP, submitted);
    } else {
        assert!(choices.is_empty(), "an exit-free loop must not request choices");
    }
    builder.build().unwrap()
}

fn scope(config: &RefinementLoopConfig, flow: Flow, request: DecisionRequest) -> Scope {
    Scope::new(
        Arc::new(flow),
        config.initial_state(request).unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    )
}

fn trace_steps(scope: &Scope) -> Vec<&str> {
    scope
        .trace()
        .entries
        .iter()
        .map(|entry| entry.step.0.as_str())
        .collect()
}

#[test]
fn default_loop_collects_refinement_text_directly_without_a_choice_round() {
    let config = RefinementLoopConfig::default();
    let mut scope = scope(
        &config,
        scripted_flow(
            &config,
            INPUT_STEP,
            &["Blue is required", "Red is required instead"],
            &[],
            false,
        ),
        request(""),
    );
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, REFINE_STEP);
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, INPUT_STEP);
    let input = input_step(false).input(&scope).unwrap();
    assert!(input.field_schema(REFINEMENT_INPUT_FIELD).is_some());
    let prompt = input.field_schema(REFINEMENT_INPUT_FIELD).unwrap()["title"]
        .as_str()
        .unwrap();
    assert!(prompt.starts_with("What size?"));
    assert!(!prompt.contains("Blue option"));
    assert!(!prompt.contains("Red option"));
    scope.advance().unwrap();
    assert_eq!(
        scope.state().get::<String>(REFINEMENT_INPUT_FIELD).unwrap(),
        "Red is required instead"
    );
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, INPUT_STEP);
    assert!(!scope.is_finished());
    assert!(scope.state().get::<String>(CHOICE_STATE_FIELD).is_none());
    let decision = scope.state().get::<DecisionState>(DECISION_STATE_FIELD).unwrap();
    assert_eq!(decision.ranking.candidate_ids, [CandidateId::from("red")]);
    assert_eq!(decision.question.prompt, "Any other requirements?");
    assert_eq!(trace_steps(&scope), [INPUT_STEP, REFINE_STEP, INPUT_STEP, REFINE_STEP]);
}

#[test]
fn configured_loop_continues_refinement_then_leaves_through_a_custom_exit() {
    let config = exit_config();
    let mut scope = scope(
        &config,
        scripted_flow(
            &config,
            INPUT_STEP,
            &["Blue is required", "Red is required instead"],
            &[CONTINUE_CHOICE, "compare"],
            false,
        ),
        request(""),
    );
    scope.advance().unwrap();
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, CHOICE_STEP);
    let before = scope
        .state()
        .get::<DecisionState>(DECISION_STATE_FIELD)
        .unwrap()
        .clone();
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, REFINE_STEP);
    assert_eq!(scope.state().get::<DecisionState>(DECISION_STATE_FIELD), Some(&before));
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, CHOICE_STEP);
    scope.advance().unwrap();
    assert!(scope.is_finished());
    assert_eq!(scope.current_step().0, "compare");
    assert_eq!(scope.state().get::<String>(CHOICE_STATE_FIELD).unwrap(), "compare");
    assert_eq!(
        scope.state().get::<DecisionRequest>(DECISION_REQUEST_STATE_FIELD),
        Some(&request(""))
    );
    assert_eq!(
        scope
            .state()
            .get::<DecisionState>(DECISION_STATE_FIELD)
            .unwrap()
            .ranking
            .candidate_ids,
        [CandidateId::from("red")]
    );
    assert_eq!(
        trace_steps(&scope),
        [INPUT_STEP, REFINE_STEP, CHOICE_STEP, REFINE_STEP, CHOICE_STEP]
    );
}

#[test]
fn failed_model_turn_retries_committed_feedback_without_another_input() {
    for config in [RefinementLoopConfig::default(), exit_config()] {
        let mut scope = scope(
            &config,
            scripted_flow(&config, INPUT_STEP, &["Blue is required"], &[], true),
            request(""),
        );
        scope.advance().unwrap();
        let before = scope
            .state()
            .get::<DecisionState>(DECISION_STATE_FIELD)
            .unwrap()
            .clone();
        assert!(scope.advance().is_err());
        assert_eq!(scope.current_step().0, REFINE_STEP);
        assert_eq!(trace_steps(&scope), [INPUT_STEP]);
        assert_eq!(scope.state().get::<DecisionState>(DECISION_STATE_FIELD), Some(&before));
        assert_eq!(
            scope.state().get::<String>(REFINEMENT_INPUT_FIELD).unwrap(),
            "Blue is required"
        );
        scope.advance().unwrap();
        assert_eq!(
            scope.current_step().0,
            config.model_turn_schema()["properties"]["next"]["enum"][0]
                .as_str()
                .unwrap()
        );
    }
}

#[test]
fn public_graph_entries_and_model_schema_agree_for_both_configurations() {
    for (config, next) in [
        (RefinementLoopConfig::default(), INPUT_STEP),
        (exit_config(), CHOICE_STEP),
    ] {
        let supplied = scope(&config, config.flow(), request("A bag"));
        assert_eq!(supplied.current_step().0, REFINE_STEP);
        assert_eq!(supplied.state().get::<String>(REFINEMENT_INPUT_FIELD).unwrap(), "A bag");
        assert_eq!(
            scope(&config, config.flow_from_input(), request("")).current_step().0,
            INPUT_STEP
        );
        assert_eq!(config.model_turn_schema()["properties"]["next"]["enum"][0], next);
        let step = config.refinement_step();
        let TemplateSpec::Template(template) = step.model_template(&supplied) else {
            panic!("non-empty candidates should request refinement");
        };
        assert_eq!(template.next_step_criteria[0].0.as_ref().unwrap().0, next);
    }
}

#[test]
fn every_configured_exit_returns_immediately_without_model_calls_or_feedback() {
    let config = exit_config();
    for choice in ["compare", "restart", "save"] {
        let mut scope = scope(
            &config,
            scripted_flow(&config, CHOICE_STEP, &[], &[choice], false),
            request("A bag"),
        );
        let before = scope
            .state()
            .get::<DecisionState>(DECISION_STATE_FIELD)
            .unwrap()
            .clone();
        scope.advance().unwrap();
        assert!(scope.is_finished());
        assert_eq!(scope.current_step().0, choice);
        assert_eq!(scope.state().get::<String>(CHOICE_STATE_FIELD).unwrap(), choice);
        assert_eq!(scope.state().get::<DecisionState>(DECISION_STATE_FIELD), Some(&before));
        assert_eq!(trace_steps(&scope), [CHOICE_STEP]);
    }
}

#[test]
fn unconfigured_choices_fail_without_committing_choice_cursor_or_trace() {
    let config = RefinementLoopConfig::new(vec![ExitChoice::new("compare", "Compare")]).unwrap();
    for id in ["select:blue", "finish", "cancel", "restart", "Compare", INPUT_STEP, ""] {
        let mut scope = scope(
            &config,
            scripted_flow(&config, CHOICE_STEP, &[], &[id], false),
            request("A bag"),
        );
        assert!(scope.advance().is_err());
        assert_eq!(scope.current_step().0, CHOICE_STEP);
        assert!(scope.trace().entries.is_empty());
        assert_eq!(scope.state().get::<String>(CHOICE_STATE_FIELD).unwrap(), "");
        assert!(!scope.is_finished());
    }
}

#[test]
fn mounting_requires_exactly_the_configured_exits_and_rejects_the_exit_free_default() {
    let config = exit_config();
    for child in [config.flow(), config.flow_from_input()] {
        for omitted in [None, Some("compare"), Some("restart"), Some("save")] {
            let mut transitions = ExitTransitions::new();
            for exit in ["compare", "restart", "save"] {
                if omitted != Some(exit) {
                    transitions = transitions.transition(exit, "done").unwrap();
                }
            }
            let parent = Flow::builder("parent")
                .entry("narrow")
                .exit("done")
                .flow("narrow", child.clone(), transitions, TraceMode::Expanded)
                .build();
            assert_eq!(parent.is_ok(), omitted.is_none());
        }
        let transitions = ExitTransitions::new()
            .transition("compare", "done")
            .unwrap()
            .transition("restart", "done")
            .unwrap()
            .transition("save", "done")
            .unwrap()
            .transition("cancel", "done")
            .unwrap();
        assert!(
            Flow::builder("parent")
                .entry("narrow")
                .exit("done")
                .flow("narrow", child, transitions, TraceMode::Expanded)
                .build()
                .is_err()
        );
    }
    let config = RefinementLoopConfig::default();
    for child in [config.flow(), config.flow_from_input()] {
        assert!(
            Flow::builder("parent")
                .entry("narrow")
                .flow("narrow", child, ExitTransitions::new(), TraceMode::Expanded)
                .build()
                .is_err()
        );
    }
}

#[test]
fn parent_routes_custom_exits_and_collects_restart_feedback_outside_the_child() {
    const APP_FEEDBACK: &str = "application_restart_feedback";
    let config = exit_config();
    for (choice, goal, feedback, target) in [
        ("compare", "Blue is required", "", "compare_products"),
        ("compare", "Nothing matches", "", "compare_products"),
        ("save", "Blue is required", "", "save_results"),
        ("restart", "Blue is required", "  broader options  ", "collect_feedback"),
        ("restart", "Blue is required", "", "collect_feedback"),
    ] {
        let parent = Flow::builder("parent")
            .entry("narrow")
            .exit("compare_products")
            .exit("save_results")
            .exit("retrieve_candidates")
            .flow(
                "narrow",
                scripted_flow(&config, REFINE_STEP, &[], &[choice], false),
                ExitTransitions::new()
                    .transition("compare", "compare_products")
                    .unwrap()
                    .transition("save", "save_results")
                    .unwrap()
                    .transition("restart", "collect_feedback")
                    .unwrap(),
                TraceMode::Expanded,
            )
            .step(
                "collect_feedback",
                Submitted::new(
                    StepBuilder::new()
                        .description("Collect a text message")
                        .with_input({
                            let mut input = InputSpec::builder();
                            let field = input
                                .field(APP_FEEDBACK, "What should change?", String::new())
                                .text_input();
                            let submit = input.submit("Send");
                            let layout = input.ui().column(vec![field, submit]);
                            input.finish(layout).unwrap()
                        })
                        .update_from(
                            APP_FEEDBACK,
                            ValueSource::Input {
                                name: APP_FEEDBACK.into(),
                            },
                        )
                        .next("retrieve_candidates")
                        .summary("Received a text message")
                        .build()
                        .unwrap(),
                    APP_FEEDBACK,
                    &[feedback],
                ),
            )
            .build()
            .unwrap();
        let state = config
            .add_state_fields(
                State::builder().field("parent", "Unrelated parent data", 7_u64).field(
                    APP_FEEDBACK,
                    "Application-owned feedback",
                    String::new(),
                ),
                request(goal),
            )
            .unwrap()
            .build()
            .unwrap();
        let mut scope = Scope::new(Arc::new(parent), state, AutoCheckpointConfig::Disabled, None);
        scope.advance().unwrap();
        assert_eq!(scope.current_step().0, target);
        assert_eq!(scope.state().get::<u64>("parent"), Some(&7));
        assert_eq!(scope.state().get::<String>(APP_FEEDBACK).unwrap(), "");
        assert_eq!(scope.state().get::<String>(CHOICE_STATE_FIELD).unwrap(), choice);
        assert_eq!(
            scope.state().get::<DecisionRequest>(DECISION_REQUEST_STATE_FIELD),
            Some(&request(goal))
        );
        let expected_ids = if goal == "Nothing matches" {
            vec![]
        } else {
            vec![CandidateId::from("blue")]
        };
        assert_eq!(
            scope
                .state()
                .get::<DecisionState>(DECISION_STATE_FIELD)
                .unwrap()
                .ranking
                .candidate_ids,
            expected_ids
        );
        let TraceSummary::SubFlow(trace) = &scope.trace().entries[0].summary else {
            panic!("expanded child trace should be retained");
        };
        assert_eq!(
            trace
                .entries
                .iter()
                .map(|entry| entry.step.0.as_str())
                .collect::<Vec<_>>(),
            [REFINE_STEP, CHOICE_STEP]
        );
        if choice == "restart" {
            assert!(!scope.is_finished());
            scope.advance().unwrap();
            assert_eq!(scope.current_step().0, "retrieve_candidates");
            assert_eq!(scope.state().get::<String>(APP_FEEDBACK).unwrap(), feedback);
            assert_eq!(trace_steps(&scope), ["narrow", "collect_feedback"]);
        }
        assert!(scope.is_finished());
    }
}

#[test]
fn empty_ranking_can_be_refined_again_in_either_graph() {
    for config in [RefinementLoopConfig::default(), exit_config()] {
        let choices = if config.choice_options().is_empty() {
            vec![]
        } else {
            vec![CONTINUE_CHOICE, "compare"]
        };
        let mut scope = scope(
            &config,
            scripted_flow(&config, REFINE_STEP, &["Blue is required"], &choices, false),
            request("Nothing matches"),
        );
        scope.advance().unwrap();
        assert!(
            scope
                .state()
                .get::<DecisionState>(DECISION_STATE_FIELD)
                .unwrap()
                .ranking
                .candidate_ids
                .is_empty()
        );
        assert!(!scope.is_finished());
        assert_eq!(
            scope.current_step().0,
            if choices.is_empty() { INPUT_STEP } else { CHOICE_STEP }
        );
        scope.advance().unwrap();
        scope.advance().unwrap();
        assert_eq!(
            scope
                .state()
                .get::<DecisionState>(DECISION_STATE_FIELD)
                .unwrap()
                .ranking
                .candidate_ids,
            [CandidateId::from("blue")]
        );
        if choices.is_empty() {
            assert_eq!(scope.current_step().0, INPUT_STEP);
            assert!(!scope.is_finished());
        } else {
            scope.advance().unwrap();
            assert!(scope.is_finished());
            assert_eq!(scope.current_step().0, "compare");
        }
    }
}
