//! Exported configuration data. Resolving these references from JSON belongs to a future runner.

use lyquid_flow::{InputSpec, ModelTemplate, StepId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{StepData, StepWiring};

/// A stable capability name and its settings, never serialized Rust code.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackConfiguration {
    pub name: String,
    pub settings: Value,
}

impl CallbackConfiguration {
    pub(crate) fn new(name: impl Into<String>, settings: &impl Serialize) -> Result<Self, String> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err("exported callback name must be nonblank".into());
        }
        Ok(Self {
            name,
            settings: serde_json::to_value(settings).map_err(|error| format!("export callback settings: {error}"))?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputConfiguration {
    Static { specification: InputSpec },
    Factory { callback: CallbackConfiguration },
    DataFactory { callback: CallbackConfiguration },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfiguration {
    pub goal: String,
    pub next: Vec<(Option<StepId>, String)>,
    pub state_updates: Vec<(String, String)>,
    pub allow_restore: bool,
}

impl From<&ModelTemplate> for ModelConfiguration {
    fn from(template: &ModelTemplate) -> Self {
        Self {
            goal: template.step_goal.clone(),
            next: template.next_step_criteria.clone(),
            state_updates: template.state_update_criteria.clone(),
            allow_restore: template.allow_restore,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionInput {
    Context,
    Proposed { field: String },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionConfiguration {
    pub callback: CallbackConfiguration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPlan {
    pub input: ActionInput,
    pub actions: Vec<ActionConfiguration>,
}

/// Serializable description of a native Step. Deserializing this data does not create a Step.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepConfiguration {
    pub version: u32,
    pub wiring: StepWiring,
    pub data: StepData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<InputConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelConfiguration>,
    pub finalization: ActionPlan,
}

impl StepConfiguration {
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|error| error.to_string())
    }
}
