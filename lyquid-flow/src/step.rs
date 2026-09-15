use std::any::Any;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::scope::{FlowError, Scope};
use crate::state::Value;
use crate::trace::TraceSummary;
use crate::turn::TurnProposal;

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

/// Step template, or a developer-selected transition that skips the model.
pub enum TemplateSpec {
    /// Step-specific context rendered with the current State and Trace before model invocation.
    Template(String),

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
