use std::any::Any;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::TurnProposal;
use crate::scope::{FlowError, Scope};
use crate::state::Value;
use crate::trace::TraceSummary;

/// Stable identifier of a Step.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StepId(pub String);

impl From<&str> for StepId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Display for StepId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Client-facing input contract for a Step.
#[derive(Clone)]
pub struct InputSpec {
    /// Prompt shown to the client.
    pub prompt: String,
    /// Stable name used to expose the submitted value to the Step.
    pub name: String,
    /// Prototype used to decode and type-check submitted input.
    pub value: Box<dyn Value>,
}

/// Runtime value accepted through an [`InputSpec`].
pub type Input = Box<dyn Value>;

/// Structured contract from which the framework builds one model-backed Step prompt.
///
/// The goal and every criterion are Tera templates with access to the current State, input, and Trace.
/// Destinations and State fields omitted from this declaration are not exposed to the model and are rejected if the
/// model nevertheless proposes them. [`Step::finalize`] may still revise an accepted proposal deterministically.
#[derive(Clone)]
pub struct ModelTemplate {
    /// Free-form instructions describing the work this Step should accomplish.
    pub step_goal: String,
    /// Next Steps or exits the model may select, paired as `(next_step, selection_criterion)`; each criterion
    /// describes when to choose that destination. `None` proposes completing a root Flow.
    pub next_step_criteria: Vec<(Option<StepId>, String)>,
    /// State fields the model may update, paired as `(field_name, update_criterion)`; each criterion describes when
    /// to update the field and what its complete replacement should contain.
    pub state_update_criteria: Vec<(String, String)>,
}

impl ModelTemplate {
    /// Creates a model template with its three authored sections.
    pub fn new(
        step_goal: impl Into<String>, next_step_criteria: Vec<(Option<StepId>, String)>,
        state_update_criteria: Vec<(String, String)>,
    ) -> Self {
        Self {
            step_goal: step_goal.into(),
            next_step_criteria,
            state_update_criteria,
        }
    }
}

/// Step template, or a developer-selected transition that skips the model.
pub enum TemplateSpec {
    /// Structured model-call contract rendered with the current State, input, and Trace before invocation.
    Template(ModelTemplate),

    /// Return a direct proposal without calling a model.
    Skip(TurnProposal),
}

/// One workflow graph vertex.
///
/// The [`Any`] bound lets the runner identify a mounted [`crate::Flow`] without adding a separate
/// registration trait or requiring Step implementations to provide downcasting methods.
pub trait Step: Any + Send + Sync {
    /// Explains this Step's purpose; `concise` requests a shorter form for model transition context.
    fn description(&self, concise: bool) -> String;

    /// Describes the input required for this Step, or returns `None` for no input.
    fn input(&self, scope: &Scope) -> Option<InputSpec>;

    /// Selects a model template using the current Scope or provides the decision directly.
    fn model_template(&self, scope: &Scope) -> TemplateSpec;

    /// Finalizes the proposed turn against a read-only Scope before it is validated and committed.
    /// Returning an error rejects the complete turn without committing its cursor, State, or Trace changes.
    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError>;
}
