//! Build ordinary `lyquid_flow::Step`s with `StructuredStepBuilder`.
//!
//! Attach Flow's `InputSpec` and `ModelTemplate`, append ordinary Rust functions for ordered
//! finalization, and configure wiring in one builder chain. Built Steps follow Flow's
//! input → model → finalize → validate/commit lifecycle. Flow owns execution and checkpoints.

mod action;
mod builder;
mod configuration;
mod context;
mod data;
mod next;
mod step;
mod wiring;

pub use builder::StructuredStepBuilder;
pub use configuration::{
    ActionConfiguration, ActionInput, ActionPlan, CallbackConfiguration, InputConfiguration, ModelConfiguration,
    StepConfiguration,
};
pub use context::ActionContext;
pub use data::{DataArgument, ModelOutput, Presence, StepData};
pub use next::{NextCase, NextStep};
pub use step::StructuredStep;
pub use wiring::{Binding, BindingTarget, StepWiring, ValueSource};

// Shaker discovers guest tests in the library artifact, including public composition coverage.
#[cfg(test)]
#[path = "../tests/composition/mod.rs"]
mod composition_tests;

#[cfg(test)]
#[path = "../tests/routing/mod.rs"]
mod routing_tests;

#[cfg(test)]
#[path = "../tests/data/mod.rs"]
mod data_tests;

// Host the input examples' guest tests without giving the examples a Cargo crate.
#[cfg(test)]
#[path = "../../steps/inputs/tests/mod.rs"]
mod input_examples;
