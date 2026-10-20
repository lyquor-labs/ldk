use std::collections::BTreeSet;
use std::sync::Arc;

use lyquid_flow::{Flow, ModelTemplate};
use lyquid_structured_step::{NextStep, StepConfiguration, StepWiring, StructuredStepBuilder};
use serde::{Serialize, de::DeserializeOwned};

use crate::definition::{Component, FlowDefinition, Node};

type NativeBuilder = lyquid_flow::FlowBuilder;
type AddStep = dyn Fn(NativeBuilder, &str) -> Result<NativeBuilder, String> + Send + Sync;

#[derive(Clone)]
struct FlowComponentRegistration {
    id: String,
    wiring: StepWiring,
    model: Result<Option<Box<ModelTemplate>>, String>,
    configuration: Result<Box<StepConfiguration>, String>,
    add: Arc<AddStep>,
}

/// Composes Step builders into an ordinary native Flow and exports their authored configuration.
/// Callers supply State and runtime services when creating a Scope.
#[derive(Clone)]
pub struct StructuredFlowBuilder {
    id: String,
    description: String,
    entries: Vec<String>,
    exits: Vec<String>,
    nodes: Vec<FlowComponentRegistration>,
}

impl StructuredFlowBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: String::new(),
            entries: vec![],
            exits: vec![],
            nodes: vec![],
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn entry(mut self, entry: impl Into<String>) -> Self {
        self.entries.push(entry.into());
        self
    }

    pub fn exit(mut self, exit: impl Into<String>) -> Self {
        self.exits.push(exit.into());
        self
    }

    pub fn step<C, O, I>(mut self, id: impl Into<String>, step: StructuredStepBuilder<C, O, I>) -> Self
    where
        C: Serialize + 'static,
        O: Serialize + 'static,
        I: DeserializeOwned + 'static,
    {
        self.nodes.push(FlowComponentRegistration {
            id: id.into(),
            wiring: step.wiring().clone(),
            model: step.configured_model().map(|model| model.map(Box::new)),
            configuration: step.configuration().map(Box::new),
            add: Arc::new(move |builder, id| Ok(builder.step(id, step.clone().build()?))),
        });
        self
    }

    fn validate(&self) -> Result<(), String> {
        nonblank(&self.id)?;
        let mut node_ids = BTreeSet::new();
        for node in &self.nodes {
            nonblank(&node.id)?;
            if !node_ids.insert(node.id.as_str()) {
                return Err(format!("duplicate node {:?}", node.id));
            }
        }
        let mut exit_ids = BTreeSet::new();
        for exit in &self.exits {
            nonblank(exit)?;
            if !exit_ids.insert(exit.as_str()) {
                return Err(format!("duplicate exit {exit:?}"));
            }
            if node_ids.contains(exit.as_str()) {
                return Err(format!("exit {exit:?} conflicts with a node"));
            }
        }
        let [entry] = self.entries.as_slice() else {
            return Err("Flow requires exactly one entry Step".into())
        };
        if !node_ids.contains(entry.as_str()) {
            return Err(format!("unknown Flow entry {entry:?}"));
        }
        let destination = |next: &Option<lyquid_flow::StepId>| -> Result<(), String> {
            if let Some(next) = next &&
                !node_ids.contains(next.0.as_str()) &&
                !exit_ids.contains(next.0.as_str())
            {
                return Err(format!("unknown destination {next}"));
            }
            Ok(())
        };
        for node in &self.nodes {
            let validation = (|| {
                match &node.wiring.next {
                    NextStep::Fixed { next } => destination(next)?,
                    NextStep::Result { cases, .. } => {
                        for case in cases {
                            destination(&case.next)?;
                        }
                    }
                    NextStep::Proposed => {}
                }
                if let Some(model) = node.model.as_ref().map_err(Clone::clone)? {
                    if model.next_step_criteria.is_empty() {
                        return Err("a model template must declare at least one next-step criterion".into());
                    }
                    let mut targets = BTreeSet::new();
                    for (next, _) in &model.next_step_criteria {
                        if !targets.insert(next) {
                            let target = next
                                .as_ref()
                                .map_or_else(|| "Flow completion".to_owned(), |step| format!("Step {step}"));
                            return Err(format!("duplicate next-step criterion for {target}"));
                        }
                        destination(next)?;
                    }
                    let mut fields = BTreeSet::new();
                    for (field, _) in &model.state_update_criteria {
                        if !fields.insert(field) {
                            return Err(format!("duplicate State update criterion for field {field}"));
                        }
                    }
                }
                Ok::<_, String>(())
            })();
            validation.map_err(|e| format!("node {:?}: {e}", node.id))?;
        }
        Ok(())
    }

    fn definition(&self) -> Result<FlowDefinition, String> {
        self.validate()?;
        let nodes = self
            .nodes
            .iter()
            .map(|node| {
                Ok(Node {
                    id: node.id.clone(),
                    component: Component::Step {
                        configuration: node
                            .configuration
                            .clone()
                            .map_err(|e| format!("node {:?}: {e}", node.id))?,
                    },
                })
            })
            .collect::<Result<_, String>>()?;
        Ok(FlowDefinition {
            version: 1,
            id: self.id.clone(),
            description: self.description.clone(),
            entry: self.entries[0].clone(),
            exits: self.exits.clone(),
            nodes,
        })
    }

    /// Validates and exports the authored graph as JSON without consuming the builder.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.definition()?).map_err(|error| error.to_string())
    }

    /// Validates and builds an ordinary native Flow. Export configuration before consuming the
    /// builder, or retain a clone for later export.
    pub fn build(self) -> Result<Flow, String> {
        self.validate()?;
        let mut builder = Flow::builder(self.id.as_str()).description(&self.description);
        for entry in &self.entries {
            builder = builder.entry(entry.as_str());
        }
        for exit in &self.exits {
            builder = builder.exit(exit.as_str());
        }
        for node in self.nodes {
            builder = (node.add)(builder, &node.id).map_err(|e| format!("node {:?}: {e}", node.id))?;
        }
        builder.build()
    }
}

fn nonblank(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        Err("Flow names must be nonblank".into())
    } else {
        Ok(())
    }
}
