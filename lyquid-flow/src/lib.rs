#![doc(html_no_source)]

//! Reusable Flow and Step for Lyquid workflows.

mod flow;
mod input;
mod prompt;
mod scope;
mod state;
mod step;
mod trace;
pub mod ui;

pub use flow::{ExitTransitions, Flow, FlowBuilder, FlowId, TraceMode};
pub use input::{FieldBuilder, Input, InputSpec, InputSpecBuilder};
pub use scope::{AutoCheckpointConfig, FlowError, InputHandle, Scope, ScopeId, ScopeSnapshot};
pub use state::{List, Mapping, State, StateBuilder, StateNamespace, StateUpdates, Value};
pub use step::{ModelTemplate, Step, StepId, TemplateSpec};
pub use trace::{Trace, TraceEntry, TraceSummary};
pub use ui::UiDocument;

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
