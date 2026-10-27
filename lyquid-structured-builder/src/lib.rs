//! Decorate existing Steps with State updates and next-Step selection.
//!
//! Model criteria use Core's model phase. Structured updates run after the wrapped finalizer,
//! then Core validates and commits the turn. Compose the resulting Steps with `Flow::builder()`.
//! The wrapped Step decides whether to call a model; structured rules never turn `Skip` into `Template`.

use lyquid_flow::{Diagnostic, FlowError, Scope, StateNamespace, StepId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod spec;
mod step;

pub use spec::StructuredSpec;
pub use step::StructuredStep;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NextCase {
    /// A local Step/exit, or root completion when `None`.
    pub next: Option<StepId>,
    pub description: String,
}

/// Candidate destinations for the structured Step.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NextStep {
    pub steps: Vec<NextCase>,
}

impl Default for NextStep {
    fn default() -> Self {
        Self {
            steps: vec![NextCase {
                next: None,
                description: "Complete the Flow".into(),
            }],
        }
    }
}

impl NextStep {
    pub fn destinations(&self) -> Vec<Option<StepId>> {
        self.steps.iter().map(|case| case.next.clone()).collect()
    }

    pub(crate) fn needs_model(&self) -> bool {
        self.steps.len() > 1
    }
}

/// The three supported sources for a State update.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueSource {
    Constant {
        value: Value,
    },
    /// Reads the current State (or submitted input), before this turn's updates are applied.
    State {
        #[serde(with = "StateNamespaceSerde")]
        namespace: StateNamespace,
        field: String,
    },
    /// Describes when a State field changes and its replacement.
    Model {
        description: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(remote = "StateNamespace", rename_all = "snake_case")]
enum StateNamespaceSerde {
    Default,
    Input,
    Tool,
}

impl ValueSource {
    pub fn constant(value: impl Into<Value>) -> Self {
        Self::Constant { value: value.into() }
    }

    pub fn reference(namespace: StateNamespace, field: impl Into<String>) -> Self {
        Self::State {
            namespace,
            field: field.into(),
        }
    }

    pub fn model(description: impl Into<String>) -> Self {
        Self::Model {
            description: description.into(),
        }
    }

    pub(crate) fn is_model(&self) -> bool {
        matches!(self, Self::Model { .. })
    }

    pub(crate) fn read(&self, scope: &Scope) -> Result<Option<Value>, FlowError> {
        match self {
            Self::Constant { value } => Ok(Some(value.clone())),
            Self::Model { .. } => Ok(None),
            Self::State { namespace, field } => {
                let value = match namespace {
                    StateNamespace::Input => scope.get(*namespace, field),
                    _ => scope.state().get_in(*namespace, field),
                }
                .ok_or_else(|| format!("missing State reference {namespace}.{field}"))?;
                Ok(Some(value.clone()))
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Diagnostic> {
        match self {
            Self::State { field, .. } => nonblank(field, "State reference"),
            Self::Model { description } => nonblank(description, "model description"),
            Self::Constant { .. } => Ok(()),
        }
    }
}

/// Rejects empty or whitespace-only values, using `label` to identify the invalid setting in the error.
fn nonblank(value: &str, label: &str) -> Result<(), Diagnostic> {
    if value.trim().is_empty() {
        Err(Diagnostic::new(label, "must be nonblank"))
    } else {
        Ok(())
    }
}
