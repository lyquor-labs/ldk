use std::fmt::Write as _;

use lyquid_flow::{Flow, FlowError, Scope, State, StateBuilder};
use multiple_choice_step::{Choice, MultipleChoiceStep};
use refinement_step::{
    DECISION_REQUEST_STATE_FIELD, DECISION_STATE_FIELD, DecisionRequest, DecisionState, REFINEMENT_INPUT_FIELD,
    RefinementStep,
};
use text_input_step::TextInputStep;

pub(crate) const INPUT_STEP: &str = "input";
pub(crate) const REFINE_STEP: &str = "refine";
pub(crate) const CHOICE_STEP: &str = "choose";

/// Committed choice ID, present only when the loop has configured exits.
pub const CHOICE_STATE_FIELD: &str = "decision_refinement_choice";
/// The built-in action that collects another message without leaving the loop.
pub const CONTINUE_CHOICE: &str = "refine";

/// An application-defined menu option whose ID is also the named Flow exit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitChoice {
    pub id: String,
    pub label: String,
}

impl ExitChoice {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
        }
    }
}

/// Immutable wiring shared by the Flow, its initial State, UI choices, and model schema.
///
/// The default has no exits or multiple-choice Step: refinement goes directly to text input.
/// A mounted child Flow requires at least one configured exit; exit-free loops run standalone.
#[derive(Clone, Debug, Default)]
pub struct RefinementLoopConfig {
    exits: Vec<ExitChoice>,
}

impl RefinementLoopConfig {
    /// Defines the available exits in menu order. `refine` is added automatically when needed.
    ///
    /// IDs and labels must be nonblank. IDs must be unique and cannot collide with the internal
    /// `input`, `refine`, or `choose` Step IDs. An empty list is equivalent to [`Self::default`].
    pub fn new(exits: Vec<ExitChoice>) -> Result<Self, FlowError> {
        for (index, exit) in exits.iter().enumerate() {
            if exit.id.trim().is_empty() || exit.label.trim().is_empty() {
                return Err(FlowError::Execution("exit IDs and labels must not be empty".to_owned()));
            }
            if [INPUT_STEP, REFINE_STEP, CHOICE_STEP].contains(&exit.id.as_str()) {
                return Err(FlowError::Execution(format!(
                    "exit ID {:?} is reserved by the loop",
                    exit.id
                )));
            }
            if exits[..index].iter().any(|other| other.id == exit.id) {
                return Err(FlowError::Execution(format!("duplicate exit ID {:?}", exit.id)));
            }
        }
        Ok(Self { exits })
    }

    /// Adds refinement State and, only for a loop with exits, a committed choice field.
    pub fn add_state_fields(&self, builder: StateBuilder, request: DecisionRequest) -> Result<StateBuilder, String> {
        let builder = refinement_step::add_state_fields(builder, request)?;
        Ok(if self.exits.is_empty() {
            builder
        } else {
            builder.field(
                CHOICE_STATE_FIELD,
                "User-selected loop action; never model-owned",
                String::new(),
            )
        })
    }

    pub fn initial_state(&self, request: DecisionRequest) -> Result<State, String> {
        self.add_state_fields(State::builder(), request)?.build()
    }

    /// Starts refinement with the goal supplied in the request.
    pub fn flow(&self) -> Flow {
        self.build_flow(REFINE_STEP)
    }

    /// Collects the initial goal before refining. Seed the request with an empty `user_request`.
    pub fn flow_from_input(&self) -> Flow {
        self.build_flow(INPUT_STEP)
    }

    /// Menu options for rendering, in order: continue refining, then the configured exits.
    /// Returns an empty list when there is no choice Step. Destinations are internal wiring;
    /// the application renders IDs and labels and submits the selected ID.
    pub fn choice_options(&self) -> Vec<Choice> {
        if self.exits.is_empty() {
            return vec![];
        }
        let mut choices = vec![Choice::new(CONTINUE_CHOICE, "Continue refining", INPUT_STEP)];
        choices.extend(
            self.exits
                .iter()
                .map(|exit| Choice::new(&exit.id, &exit.label, exit.id.as_str())),
        );
        choices
    }

    /// Provider-neutral response schema with the successor used by this configured graph.
    pub fn model_turn_schema(&self) -> serde_json::Value {
        self.refinement_step().model_turn_schema()
    }

    pub(crate) fn refinement_step(&self) -> RefinementStep {
        RefinementStep::new(if self.exits.is_empty() { INPUT_STEP } else { CHOICE_STEP })
    }

    pub(crate) fn choice_step(&self) -> Option<MultipleChoiceStep> {
        if self.exits.is_empty() {
            return None;
        }
        Some(
            MultipleChoiceStep::new(
                CHOICE_STATE_FIELD,
                "What would you like to do next?",
                self.choice_options(),
            )
            .expect("validated loop exits and the built-in continue action form a valid menu")
            .with_prompt(|scope| {
                let mut prompt = decision_summary(scope);
                prompt.push_str("\nChoose an action ID below. Choose refine to enter a preference or requirement.");
                prompt
            }),
        )
    }

    fn build_flow(&self, entry: &str) -> Flow {
        let mut builder = Flow::builder("refinement-loop")
            .description("Help a user narrow and rank a fixed caller-provided candidate list")
            .entry(entry)
            .step(INPUT_STEP, input_step())
            .step(REFINE_STEP, self.refinement_step());
        if let Some(choice) = self.choice_step() {
            builder = builder.step(CHOICE_STEP, choice);
            for exit in &self.exits {
                builder = builder.exit(exit.id.as_str());
            }
        }
        builder
            .build()
            .expect("validated loop configuration must produce a valid Flow graph")
    }
}

pub(crate) fn input_step() -> TextInputStep {
    TextInputStep::new(REFINEMENT_INPUT_FIELD, "What are you looking for?", REFINE_STEP).with_prompt(refinement_prompt)
}

fn refinement_prompt(scope: &Scope) -> String {
    let mut prompt = decision_summary(scope);
    prompt.push_str("\nUse the question as a hint if useful, or state any preference or requirement directly.");
    prompt
}

fn decision_summary(scope: &Scope) -> String {
    let request = scope
        .state()
        .get::<DecisionRequest>(DECISION_REQUEST_STATE_FIELD)
        .expect("the refinement Flow requires its request State");
    let decision = scope
        .state()
        .get::<DecisionState>(DECISION_STATE_FIELD)
        .expect("the refinement Flow requires its decision State");
    let mut prompt = if decision.question.prompt.trim().is_empty() {
        "What are you looking for?".to_owned()
    } else {
        decision.question.prompt.clone()
    };
    prompt.push_str("\n\nCurrent candidates:\n");
    for candidate_id in &decision.ranking.candidate_ids {
        if let Some(candidate) = request
            .candidates
            .iter()
            .find(|candidate| candidate.id == *candidate_id)
        {
            writeln!(&mut prompt, "- {}: {}", candidate.id, candidate.description)
                .expect("writing to a String cannot fail");
        }
    }
    prompt
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
