#![doc(html_no_source)]

//! Reusable Flow and Step for Lyquid workflows.

mod error;
mod flow;
mod input;
mod prompt;
mod scope;
pub mod service;
mod state;
mod step;
mod tool;
mod trace;
pub mod types;
pub mod ui;

pub use error::{BuildError, Diagnostic, Diagnostics};

pub use flow::{ExitTransitions, Flow, FlowBuilder, FlowId, TraceMode};
pub use input::{FieldBuilder, Input, InputError, InputSpec, InputSpecBuilder};
pub use scope::{AutoCheckpointConfig, FlowError, InputHandle, Scope, ScopeId, ScopeSnapshot};
pub use state::{State, StateBuilder, StateNamespace, StateUpdates};
pub use step::{ModelTemplate, Step, StepId, TemplateSpec};
pub use tool::{ToolAction, ToolManifest, ToolParameter, ToolStep};
pub use trace::{Trace, TraceEntry, TraceSummary};
pub use types::Type;
pub use types::json_schema::{check as check_json_schema, validate_json_schema};
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
