//! Declarative State bindings, result mapping, and transitions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::NextStep;

/// A value readable by a binding. Context and Result become available after preparation/action.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueSource {
    /// Selects a nested value without rendering it as text.
    Select {
        source: Box<Self>,
        pointer: String,
    },
    State {
        field: String,
    },
    Input {
        name: String,
    },
    /// Uses an explicit fallback only when an optional interactive field was omitted.
    InputOr {
        name: String,
        default: JsonValue,
    },
    ExecutionId,
    Context {
        name: String,
    },
    Result {
        pointer: String,
    },
    ModelResponse {
        pointer: String,
    },
    ActionResult {
        action: String,
        pointer: String,
    },
    Constant {
        value: JsonValue,
    },
}

impl ValueSource {
    pub fn at(self, pointer: impl Into<String>) -> Self {
        Self::Select {
            source: Box::new(self),
            pointer: pointer.into(),
        }
    }

    pub(crate) fn root(&self) -> &Self {
        match self {
            Self::Select { source, .. } => source.root(),
            source => source,
        }
    }
}

/// The destination determines the phase: prepare a context argument or stage a State replacement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BindingTarget {
    Context { name: String },
    State { field: String },
}

/// One directed mapping. List order never introduces dependencies between bindings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub from: ValueSource,
    pub to: BindingTarget,
}

/// Data for saving and loading a `StructuredStepBuilder`'s wiring: description, bindings, routing, and trace.
/// Import/export it through `StructuredStepBuilder::with_wiring` and `StructuredStepBuilder::wiring`.
/// Input specifications, model templates, and executable callbacks are supplied separately on the builder;
/// this data contains only the wiring portion of a Step. The builder's `build` method produces
/// the runnable Step using Flow's existing lifecycle.
///
/// Result pointers use JSON Pointer syntax (`""` means the complete result). Summary templates
/// expose committed `state`, prepared `context`, the final `result`, `model_response`, and named
/// `actions` outputs. Destinations are local Step/exit IDs, as with handwritten Steps.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepWiring {
    pub description: String,
    pub bindings: Vec<Binding>,
    pub next: NextStep,
    pub summary: String,
}
