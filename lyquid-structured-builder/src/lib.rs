//! Decorate existing Steps with State updates and next-Step selection.
//!
//! Model criteria use Core's model phase. Structured updates run after the wrapped finalizer,
//! then Core validates and commits the turn. Compose the resulting Steps with `Flow::builder()`.
//! The wrapped Step decides whether to call a model; structured rules never turn `Skip` into `Template`.
//! Mount wrapped child Flows through [`lyquid_flow::FlowBuilder::flow_with`].
//! Initialize their State with [`state_builder`].

use lyquid_flow::{State, StateBuilder, Type};
use serde_json::Value;

mod spec;
mod step;

pub use spec::{Input, NextStep, Output, StructuredSpec, ValueSpec};
pub use step::StructuredStep;

/// Starts State construction with entry arguments in `__input` and null in `__output`.
/// Both fields use [`Type::Dynamic`]. Pass `[]` for no arguments.
/// Consumers check argument types when they use the values.
pub fn state_builder(inputs: impl IntoIterator<Item = (String, Value)>) -> StateBuilder {
    State::builder()
        .field(
            "__input",
            "Step arguments",
            Type::Dynamic,
            Value::Object(inputs.into_iter().collect()),
        )
        .field("__output", "Step result", Type::Dynamic, Value::Null)
}
