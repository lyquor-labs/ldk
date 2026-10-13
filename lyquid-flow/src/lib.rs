#![doc(html_no_source)]

//! Reusable Flow and Step for Lyquid workflows.

mod flow;
mod input;
mod prompt;
mod scope;
pub mod service;
mod state;
mod step;
mod trace;
pub mod ui;

pub use flow::{ExitTransitions, Flow, FlowBuilder, FlowId, TraceMode};
pub use input::schema::check as check_json_schema;
pub use input::{FieldBuilder, Input, InputError, InputSpec, InputSpecBuilder};
pub use scope::{AutoCheckpointConfig, FlowError, InputHandle, Scope, ScopeId, ScopeSnapshot};
pub use state::{List, Mapping, State, StateBuilder, StateNamespace, StateUpdates, Value};
pub use step::{ModelTemplate, Step, StepId, TemplateSpec};
pub use trace::{Trace, TraceEntry, TraceSummary};
pub use ui::{UiDocument, ViewSpec};

/// Proposed result of one Step turn, subject to Finalization and Flow validation.
#[derive(Clone)]
pub enum TurnProposal {
    /// Advance within the containing Flow or complete it with optional State replacements.
    Advance {
        /// Next Step, mounted entry, or exit; `None` completes the current Flow.
        next: Option<StepId>,
        /// Proposed whole-field State replacements.
        updates: StateUpdates,
    },
    /// Restore one saved Scope belonging to the containing Flow execution.
    Restore {
        /// Flow-local checkpoint ID.
        scope: ScopeId,
    },
}

/// Validate a JSON value against a checked schema. Recursive validation is limited to 128 nested evaluations.
/// Exceeding the limit aborts validation, including within schema composition.
/// This limit applies to this entry point only; `InputSpec` validation is unchanged.
pub fn validate_json_schema(schema: &serde_json::Value, value: &serde_json::Value, path: &str) -> Result<(), String> {
    input::schema::validate_bounded(schema, value, path).map_err(|error| error.to_string())
}
