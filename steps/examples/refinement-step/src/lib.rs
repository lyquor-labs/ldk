//! One example refinement turn for the refinement loop Flow.
//!
//! StructuredStepBuilder composes its prompt, typed bindings, domain actions, and result writes.
//! The preceding action supplies a non-empty candidate list.
//! Its State fields and decision contract are specific to this example. It does not
//! collect user input, retrieve candidates, select a provider, or wire a refinement loop.

mod schema;
mod step;
mod types;

pub use schema::model_turn_schema;
pub use step::{
    DECISION_REQUEST_STATE_FIELD, DECISION_STATE_FIELD, REFINEMENT_INPUT_FIELD, RefinementContext, add_state_fields,
    initial_state, refinement_step,
};
pub use types::{
    Candidate, CandidateId, CandidateRanking, DecisionRequest, DecisionState, GoalFrame, RefinementQuestion,
};

// Shaker discovers guest tests in the library artifact, including this public composition coverage.
#[cfg(test)]
#[path = "../tests/composition/mod.rs"]
mod composition_tests;
