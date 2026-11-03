//! Decorate existing Steps with State updates and next-Step selection.
//!
//! Model criteria use Core's model phase. Structured updates run after the wrapped finalizer,
//! then Core validates and commits the turn. Compose the resulting Steps with `Flow::builder()`.
//! The wrapped Step decides whether to call a model; structured rules never turn `Skip` into `Template`.
//! Mount wrapped child Flows through [`lyquid_flow::FlowBuilder::flow_with`].

mod spec;
mod step;

pub use spec::{Input, NextStep, Output, StructuredSpec, ValueSpec};
pub use step::StructuredStep;
