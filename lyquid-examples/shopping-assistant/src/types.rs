use lyquid_flow::Value;
use serde::{Deserialize, Serialize};

/// Application-supplied goal for one shopping Scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShoppingRequest {
    pub user_request: String,
}

/// Parent-owned state carried across candidate aggregation rounds.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShoppingSearchState {
    pub aggregation_round: u64,
    pub restart_feedback: Vec<String>,
}

impl ShoppingRequest {
    pub fn new(user_request: impl Into<String>) -> Self {
        Self {
            user_request: user_request.into(),
        }
    }
}

impl Value for ShoppingRequest {
    fn encode(&self) -> String {
        serde_json::to_string(self).expect("ShoppingRequest serialization cannot fail")
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

impl Value for ShoppingSearchState {
    fn encode(&self) -> String {
        serde_json::to_string(self).expect("ShoppingSearchState serialization cannot fail")
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
