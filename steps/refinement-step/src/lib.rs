//! One reusable refinement turn over fixed, caller-provided candidates.
//!
//! This crate owns the decision types, model contract, and proposal validation. It does not
//! collect user input, retrieve candidates, select a provider, or wire a refinement loop.

mod schema;
mod step;
mod types;

pub use schema::model_turn_schema;
pub use step::{
    DECISION_REQUEST_STATE_FIELD, DECISION_STATE_FIELD, REFINEMENT_INPUT_FIELD, RefinementStep, add_state_fields,
    initial_state,
};
pub use types::{
    Candidate, CandidateId, CandidateRanking, DecisionRequest, DecisionState, GoalFrame, RefinementQuestion,
};

// Shaker discovers guest tests in the library artifact, including this public composition coverage.
#[cfg(test)]
#[path = "../tests/composition/mod.rs"]
mod composition_tests;
