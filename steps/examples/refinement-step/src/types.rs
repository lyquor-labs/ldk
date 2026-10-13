use std::fmt;

use lyquid_flow::Value;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Stable application-supplied identity for one candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct CandidateId(pub String);

impl CandidateId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl From<&str> for CandidateId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl From<String> for CandidateId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl fmt::Display for CandidateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Model-visible projection of a candidate owned by the calling application.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: CandidateId,
    /// Caller-provided facts the model may use to compare this candidate.
    pub description: String,
}

impl Candidate {
    pub fn new(id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: CandidateId::new(id),
            description: description.into(),
        }
    }
}

/// Immutable input used to initialize one decision execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    pub user_request: String,
    /// The preceding action must supply at least one candidate before refinement runs.
    #[schemars(length(min = 1))]
    pub candidates: Vec<Candidate>,
}

impl DecisionRequest {
    pub fn new(user_request: impl Into<String>, candidates: Vec<Candidate>) -> Self {
        Self {
            user_request: user_request.into(),
            candidates,
        }
    }
}

/// Current structured interpretation of the user's goal.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoalFrame {
    /// Requirements the user stated as mandatory.
    pub hard_constraints: Vec<String>,
    /// Desirable but revisable qualities, including vague or uncertain preferences.
    pub soft_preferences: Vec<String>,
}

/// Ordered candidate identities that remain in the decision.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateRanking {
    pub candidate_ids: Vec<CandidateId>,
}

/// Model-generated question offered as an optional hint for the next refinement turn.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefinementQuestion {
    pub prompt: String,
}

/// Complete model-owned state for one decision-refinement turn.
///
/// Keeping the goal, ranking, and next question in one value makes each model update atomic: a
/// turn cannot commit only part of the decision while silently retaining the rest from an older
/// turn.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionState {
    pub goal: GoalFrame,
    pub ranking: CandidateRanking,
    pub question: RefinementQuestion,
}

macro_rules! impl_json_value {
    ($type:ty) => {
        impl Value for $type {
            fn encode(&self) -> String {
                serde_json::to_string(self).expect(concat!(stringify!($type), " serialization cannot fail"))
            }

            fn decode(&self, model_output: &str) -> Result<Box<dyn Value>, String> {
                serde_json::from_str::<Self>(model_output)
                    .map(|value| Box::new(value) as Box<dyn Value>)
                    .map_err(|error| error.to_string())
            }

            fn clone_box(&self) -> Box<dyn Value> {
                Box::new(self.clone())
            }
        }
    };
}

impl_json_value!(DecisionRequest);
impl_json_value!(GoalFrame);
impl_json_value!(CandidateRanking);
impl_json_value!(RefinementQuestion);
impl_json_value!(DecisionState);
