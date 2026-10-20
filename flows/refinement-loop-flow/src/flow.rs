use lyquid_flow::{
    Flow, FlowError, InputSpec, Scope, State, StateBuilder, StateNamespace, StateUpdates, Step, TemplateSpec,
    TraceSummary, TurnProposal,
};
use lyquid_structured_step::{StructuredStepBuilder, ValueSource};
use refinement_step::{DECISION_STATE_FIELD, DecisionRequest, DecisionState, REFINEMENT_INPUT_FIELD};

pub(crate) const INPUT_STEP: &str = "input";
pub(crate) const REFINE_STEP: &str = "refine";
pub(crate) const CHOICE_STEP: &str = "choose";

/// Committed choice ID, present only when the loop has configured exits.
pub const CHOICE_STATE_FIELD: &str = "decision_refinement_choice";
/// The built-in action that collects another message without leaving the loop.
pub const CONTINUE_CHOICE: &str = "refine";

/// A menu option's submitted ID and label. Configured application options name Flow exits;
/// [`RefinementLoopConfig::choice_options`] also includes the built-in refine action.
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
/// The default has no exits: refinement goes directly to text input. With exits, one form collects
/// feedback and the chosen action together.
/// A mounted child Flow requires at least one configured exit; exit-free loops run standalone.
#[derive(Clone, Debug, Default)]
pub struct RefinementLoopConfig {
    exits: Vec<ExitChoice>,
    available: Option<fn(&Scope, &ExitChoice) -> bool>,
    nonblank: bool,
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
        Ok(Self {
            exits,
            available: None,
            nonblank: false,
        })
    }

    /// Restricts configured exits using committed application State without changing exit wiring.
    /// The built-in `refine` action remains available even when every exit is filtered out.
    pub fn with_available(mut self, available: fn(&Scope, &ExitChoice) -> bool) -> Self {
        self.available = Some(available);
        self
    }

    /// Requires nonblank feedback in the loop's text input contract.
    pub fn nonblank(mut self) -> Self {
        self.nonblank = true;
        self
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
    /// Returns an empty list when there is no choice Step. The application renders IDs and labels
    /// and submits the selected ID; the loop owns routing to refinement or the named exit.
    pub fn choice_options(&self) -> Vec<ExitChoice> {
        if self.exits.is_empty() {
            return vec![];
        }
        let mut choices = vec![ExitChoice::new(CONTINUE_CHOICE, "Refine")];
        choices.extend(self.exits.iter().cloned());
        choices
    }

    /// Provider-neutral response schema with the successor used by this configured graph.
    pub fn model_turn_schema(&self) -> serde_json::Value {
        refinement_step::model_turn_schema(self.refinement_next())
    }

    fn refinement_next(&self) -> &'static str {
        if self.exits.is_empty() { INPUT_STEP } else { CHOICE_STEP }
    }

    pub(crate) fn refinement_step(&self) -> impl Step {
        refinement_step::refinement_step(self.refinement_next())
    }

    pub(crate) fn choice_step(&self) -> Option<RefinementInputStep> {
        (!self.exits.is_empty()).then(|| RefinementInputStep { config: self.clone() })
    }

    fn build_flow(&self, entry: &str) -> Flow {
        let mut builder = Flow::builder("refinement-loop")
            .description("Help a user narrow and rank a fixed caller-provided candidate list")
            .entry(entry)
            .step(INPUT_STEP, input_step(self.nonblank))
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

pub(crate) fn input_step(nonblank: bool) -> impl Step {
    StructuredStepBuilder::new()
        .description("Collect a text message")
        .with_input_factory(move |scope| {
            let mut input = InputSpec::builder();
            let field = input.field(REFINEMENT_INPUT_FIELD, refinement_prompt(scope), String::new());
            let field = if nonblank { field.non_blank() } else { field }.text_input();
            let submit = input.submit("Send");
            let layout = input.ui().column(vec![field, submit]);
            input.finish(layout).expect("valid refinement text input")
        })
        .update_from(
            REFINEMENT_INPUT_FIELD,
            ValueSource::Input {
                name: REFINEMENT_INPUT_FIELD.into(),
            },
        )
        .next(REFINE_STEP)
        .summary("Received a text message")
        .build()
        .expect("valid refinement input wiring")
}

fn refinement_prompt(scope: &Scope) -> String {
    let decision = scope
        .state()
        .get::<DecisionState>(DECISION_STATE_FIELD)
        .expect("the refinement Flow requires its decision State");
    if decision.question.prompt.trim().is_empty() {
        "What would you like to change?".to_owned()
    } else {
        decision.question.prompt.clone()
    }
}

/// Collect feedback and its action in one deterministic input turn.
pub(crate) struct RefinementInputStep {
    config: RefinementLoopConfig,
}

impl RefinementInputStep {
    fn choices(&self, scope: &Scope) -> Vec<ExitChoice> {
        self.config
            .choice_options()
            .into_iter()
            .filter(|choice| {
                choice.id == CONTINUE_CHOICE || self.config.available.is_none_or(|available| available(scope, choice))
            })
            .collect()
    }
}

impl Step for RefinementInputStep {
    fn description(&self, _: bool) -> String {
        "Refine your preferences".to_owned()
    }

    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        let choices = self.choices(scope);
        let mut builder = InputSpec::builder();
        builder
            .field(CHOICE_STATE_FIELD, "Action", String::new())
            .choices(choices.iter().map(|choice| (choice.id.clone(), choice.label.clone())));
        let mut content = vec![builder.ui().text(refinement_prompt(scope))];
        let feedback = builder
            .field(REFINEMENT_INPUT_FIELD, "Feedback", String::new())
            .required_when(CHOICE_STATE_FIELD, [CONTINUE_CHOICE]);
        let feedback = if self.config.nonblank {
            feedback.non_blank_when(CHOICE_STATE_FIELD, [CONTINUE_CHOICE])
        } else {
            feedback
        };
        content.push(feedback.text_area());
        let buttons = choices
            .iter()
            .map(|choice| builder.submit_with(&choice.label, [(CHOICE_STATE_FIELD, choice.id.clone())]))
            .collect();
        content.push(builder.ui().row(buttons));
        let root = builder.ui().column(content);
        Some(builder.finish(root).expect("valid refinement input declaration"))
    }

    fn model_template(&self, _: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: None,
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let TurnProposal::Advance { next, updates } = proposal else {
            return Err(FlowError::Execution(
                "refinement input does not allow restore proposals".into(),
            ));
        };
        let choice = scope
            .get::<String>(StateNamespace::Input, CHOICE_STATE_FIELD)
            .and_then(|id| self.choices(scope).into_iter().find(|choice| choice.id == *id))
            .ok_or_else(|| FlowError::Execution("invalid refinement action".into()))?;
        let mut accepted = StateUpdates::default();
        if choice.id == CONTINUE_CHOICE {
            let feedback = scope
                .get::<String>(StateNamespace::Input, REFINEMENT_INPUT_FIELD)
                .ok_or_else(|| FlowError::Execution("missing refinement feedback".into()))?;
            if self.config.nonblank && feedback.trim().is_empty() {
                return Err(FlowError::Execution("refinement feedback must not be blank".into()));
            }
            accepted.set(REFINEMENT_INPUT_FIELD.into(), Some(Box::new(feedback.clone())));
        }
        accepted.set(CHOICE_STATE_FIELD.into(), Some(Box::new(choice.id.clone())));
        *next = Some(if choice.id == CONTINUE_CHOICE {
            REFINE_STEP.into()
        } else {
            choice.id.as_str().into()
        });
        *updates = accepted;
        Ok(TraceSummary::Summary(format!("Chose {}", choice.id)))
    }
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod tests;
