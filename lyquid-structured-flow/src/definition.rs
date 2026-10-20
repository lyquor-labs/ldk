//! Internal representation for JSON export, not the Configurable Flow construction API.

use lyquid_structured_step::StepConfiguration;

use serde::Serialize;

#[derive(Serialize)]
pub(super) struct FlowDefinition {
    pub(super) version: u32,
    pub(super) id: String,
    pub(super) description: String,
    pub(super) entry: String,
    pub(super) exits: Vec<String>,
    pub(super) nodes: Vec<Node>,
}

#[derive(Serialize)]
pub(super) struct Node {
    pub(super) id: String,
    pub(super) component: Component,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Component {
    Step { configuration: Box<StepConfiguration> },
}
