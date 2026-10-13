#![doc(html_no_source)]

//! Example Flow for narrowing and ranking over a fixed, caller-provided candidate list.
//!
//! Applications own candidate retrieval, selection, model configuration, and session interaction.
//! By default, refinement goes directly to text input. Configuring exits adds a combined feedback
//! form with a Refine button and those exits. Restart feedback and handling belong to the parent.

mod flow;

pub use flow::{CHOICE_STATE_FIELD, CONTINUE_CHOICE, ExitChoice, RefinementLoopConfig};
pub use refinement_step::{
    Candidate, CandidateId, CandidateRanking, DECISION_REQUEST_STATE_FIELD, DECISION_STATE_FIELD, DecisionRequest,
    DecisionState, GoalFrame, REFINEMENT_INPUT_FIELD, RefinementQuestion,
};

// Shaker discovers guest tests in the library artifact, including public composition coverage.
#[cfg(test)]
#[path = "../tests/composition/mod.rs"]
mod composition_tests;
