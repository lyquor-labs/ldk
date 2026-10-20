//! Compose typed Step builders for the ordinary `lyquid-flow` runtime.
//! JSON export contains configuration only; JSON execution belongs to a separate future runner.

mod builder;
mod definition;

pub use builder::StructuredFlowBuilder;
pub use lyquid_structured_step::{StructuredStepBuilder, ValueSource};

#[cfg(test)]
#[path = "../tests/graphs/mod.rs"]
mod tests;
