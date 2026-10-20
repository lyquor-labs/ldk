use lyquid::prelude::HashMap;
use serde_json::{Map, Value as JsonValue, json};

use crate::{Step, Value};

/// A non-model Step whose operations are described to the selecting model Step.
/// Register with [`crate::FlowBuilder::tool_step`] to expose its manifest.
pub trait ToolStep: Step {
    fn manifest(&self) -> ToolManifest;
}

#[derive(Clone)]
pub struct ToolManifest {
    pub actions: HashMap<String, ToolAction>,
}

#[derive(Clone)]
pub struct ToolAction {
    pub name: String,
    pub description: String,
    pub parameters: HashMap<String, ToolParameter>,
}

#[derive(Clone)]
pub struct ToolParameter {
    field: Box<dyn Value>,
    description: String,
    required: bool,
}

impl ToolParameter {
    pub fn new<V: Value>(description: impl Into<String>, field: V) -> Self {
        Self {
            field: Box::new(field),
            description: description.into(),
            required: false,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

impl ToolManifest {
    pub(super) fn prompt_json(&self) -> Result<JsonValue, String> {
        let actions = self
            .actions
            .iter()
            .map(|(name, action)| {
                let parameters = action
                    .parameters
                    .iter()
                    .map(|(name, parameter)| {
                        let value = serde_json::from_str::<JsonValue>(&parameter.field.encode())
                            .map_err(|error| format!("invalid tool parameter {name}: {error}"))?;
                        Ok((
                            name.clone(),
                            json!({
                                "description": parameter.description,
                                "required": parameter.required,
                                "value": value,
                            }),
                        ))
                    })
                    .collect::<Result<Map<_, _>, String>>()?;
                Ok((
                    name.clone(),
                    json!({
                        "name": action.name,
                        "description": action.description,
                        "parameters": parameters,
                    }),
                ))
            })
            .collect::<Result<Map<_, _>, String>>()?;
        Ok(json!({ "actions": actions }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lyquid::prelude::{Mutex, new_hashmap};
    use lyquid_test::test;

    use super::*;
    use crate::{
        AutoCheckpointConfig, Flow, FlowError, InputSpec, ModelTemplate, Scope, State, StateNamespace, StateUpdates,
        TemplateSpec, TraceSummary, TurnProposal,
    };

    const MODEL_OUTPUT: &str =
        r#"{"type":"advance","next":"catalog","updates":{"method":"search","keywords":"coffee"}}"#;

    fn template() -> ModelTemplate {
        ModelTemplate::new(
            "Find products",
            vec![
                (Some("catalog".into()), "Search the catalog".into()),
                (Some("ordinary".into()), "Run an ordinary Step".into()),
                (None, "Finished".into()),
            ],
            vec![
                ("method".into(), "Select the catalog operation".into()),
                ("keywords".into(), "Supply the search query".into()),
            ],
        )
    }

    struct Decide {
        output: String,
    }

    impl Step for Decide {
        fn description(&self, _: bool) -> String {
            "Choose products".into()
        }
        fn input(&self, _: &Scope) -> Option<InputSpec> {
            None
        }

        fn model_template(&self, scope: &Scope) -> TemplateSpec {
            TemplateSpec::Skip(crate::prompt::parse_response(scope.state(), &template(), &self.output).unwrap())
        }

        fn finalize(&self, _: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            let TurnProposal::Advance { updates, .. } = proposal else {
                unreachable!()
            };
            for name in ["method", "keywords"] {
                let value = updates.get::<String>(name).unwrap().clone();
                updates.set_in(StateNamespace::Tool, name.into(), Some(Box::new(value)));
            }
            Ok(TraceSummary::Summary("Selected catalog".into()))
        }
    }

    #[derive(Clone)]
    struct Catalog {
        model_backed: bool,
        executions: Arc<Mutex<Vec<JsonValue>>>,
    }

    impl Catalog {
        fn search(&self, query: &str) -> JsonValue {
            self.executions
                .lock()
                .push(json!({"method": "search", "keywords": query}));
            json!(
                ["coffee", "tea"]
                    .into_iter()
                    .filter(|item| item.contains(query))
                    .collect::<Vec<_>>()
            )
        }
    }

    impl ToolStep for Catalog {
        fn manifest(&self) -> ToolManifest {
            let mut parameters = new_hashmap();
            parameters.insert(
                "query".into(),
                ToolParameter::new("Search terms", String::new()).required(),
            );
            parameters.insert("limit".into(), ToolParameter::new("Result limit", 0_u64));
            let action = ToolAction {
                name: "search".into(),
                description: "Search products".into(),
                parameters,
            };
            let mut actions = new_hashmap();
            actions.insert(action.name.clone(), action);
            ToolManifest { actions }
        }
    }

    impl Step for Catalog {
        fn description(&self, _: bool) -> String {
            "Catalog".into()
        }

        fn input(&self, _: &Scope) -> Option<InputSpec> {
            None
        }

        fn model_template(&self, _: &Scope) -> TemplateSpec {
            if self.model_backed {
                TemplateSpec::Template(template())
            } else {
                TemplateSpec::Skip(TurnProposal::Advance {
                    next: None,
                    updates: StateUpdates::default(),
                })
            }
        }

        fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            let state = scope.state();
            let method = state.get_in::<String>(StateNamespace::Tool, "method").unwrap();
            let query = state.get_in::<String>(StateNamespace::Tool, "keywords").unwrap();
            let results = match method.as_str() {
                "search" => self.search(query),
                _ => return Err(format!("unknown catalog operation {method}").into()),
            };
            let TurnProposal::Advance { updates, .. } = proposal else {
                unreachable!()
            };
            updates.set("results".into(), Some(Box::new(results)));
            Ok(TraceSummary::Summary("Searched catalog".into()))
        }
    }

    fn fixture(output: &str, model_backed: bool) -> (Arc<Flow>, Scope, Catalog) {
        let catalog = Catalog {
            model_backed,
            executions: Arc::new(Mutex::new(Vec::new())),
        };
        let flow = Arc::new(
            Flow::builder("shopping")
                .entry("decide")
                .step("decide", Decide { output: output.into() })
                .tool_step("catalog", catalog.clone())
                .tool_step("hidden", catalog.clone())
                .step("ordinary", catalog.clone())
                .build()
                .unwrap(),
        );
        let state = State::builder()
            .field_in(StateNamespace::Tool, "method", "Tool operation", String::new())
            .field_in(StateNamespace::Tool, "keywords", "Tool query", String::new())
            .field("method", "Catalog operation", String::new())
            .field("keywords", "Search query", String::new())
            .field("results", "Matching products", json!([]))
            .build()
            .unwrap();
        let scope = Scope::new(flow.clone(), state, AutoCheckpointConfig::Disabled, None);
        (flow, scope, catalog)
    }

    #[test]
    fn renders_model_prompt_with_tool_manifest() {
        let (flow, scope, _) = fixture(MODEL_OUTPUT, false);
        let request = crate::prompt::build_request("model", &template(), &flow, &scope).unwrap();
        let system = request.system.unwrap();
        let (_, encoded) = system
            .split_once("# Response contract\nReturn exactly one JSON object matching this contract:\n")
            .unwrap();
        let contract: JsonValue = serde_json::from_str(encoded).unwrap();
        let options = contract["advance"]["next"]["options"].as_array().unwrap();
        assert_eq!(options.len(), 3);
        assert_eq!(options[0]["value"], "catalog");
        let action = &options[0]["tool"]["actions"]["search"];
        assert_eq!(action["name"], "search");
        assert_eq!(action["description"], "Search products");
        assert_eq!(action["parameters"]["query"]["required"], true);
        assert_eq!(action["parameters"]["query"]["value"], "");
        assert_eq!(action["parameters"]["limit"]["required"], false);
        assert_eq!(options[1]["value"], "ordinary");
        assert!(options[1].get("tool").is_none());
        assert!(options[2].get("tool").is_none());
        assert_eq!(contract["advance"]["updates"]["fields"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn executes_model_selected_tool_action() {
        for keywords in ["coffee", "tea"] {
            let mut output: JsonValue = serde_json::from_str(MODEL_OUTPUT).unwrap();
            output["updates"]["keywords"] = json!(keywords);
            let (_, mut scope, catalog) = fixture(&output.to_string(), false);

            scope.advance().unwrap();
            assert_eq!(scope.current_step().0, output["next"].as_str().unwrap());
            assert_eq!(
                scope.state().to_json_in(StateNamespace::Tool).unwrap(),
                output["updates"]
            );
            assert!(catalog.executions.lock().is_empty());

            scope.advance().unwrap();
            assert_eq!(*catalog.executions.lock(), vec![output["updates"].clone()]);
            assert_eq!(scope.state().get::<JsonValue>("results"), Some(&json!([keywords])));
            assert!(scope.is_finished());
            assert_eq!(scope.trace().entries.len(), 2);
        }
    }

    #[test]
    fn rejects_model_execution_in_tool_step() {
        let (_, mut scope, _) = fixture(MODEL_OUTPUT, true);
        scope.advance().unwrap();
        assert!(
            scope
                .advance()
                .unwrap_err()
                .to_string()
                .contains("must skip model execution")
        );
        assert_eq!(scope.current_step().0, "catalog");
        assert_eq!(scope.trace().entries.len(), 1);
    }
}
