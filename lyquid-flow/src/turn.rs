use crate::scope::ScopeId;
use crate::state::StateUpdates;
use crate::step::StepId;

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
