//! Finite, declared destinations selected by a fixed target or a string result.

use lyquid_flow::StepId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextCase {
    pub value: String,
    pub next: Option<StepId>,
}

/// Fixed and result routing exclude model restores. Result routing selects a declared case,
/// never an arbitrary destination supplied by the action.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NextStep {
    Fixed {
        next: Option<StepId>,
    },
    Result {
        pointer: String,
        cases: Vec<NextCase>,
    },
    /// Keeps model routing, including restores permitted by the model template.
    Proposed,
}
