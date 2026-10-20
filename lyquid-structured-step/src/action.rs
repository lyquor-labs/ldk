//! Reusable finalization operations over typed context and Flow's existing turn proposal.

use std::sync::Arc;

use lyquid_flow::{FlowError, ModelTemplate, Scope, StateUpdates, Value};
use lyquid_llm::ModelResponse;
use serde::Serialize;
use serde_json::{Map, Value as JsonValue};

use crate::{ActionContext, ActionInput, ActionPlan};

type RunAction<C, O> = dyn Fn(
        &C,
        &StateUpdates,
        Option<&ModelResponse>,
        &Map<String, JsonValue>,
        &mut Map<String, JsonValue>,
    ) -> Result<O, FlowError>
    + Send
    + Sync;
type ValidateAction = dyn Fn(&Scope, Option<&ModelTemplate>) -> Result<(), FlowError> + Send + Sync;

/// An ordered finalization chain that reads context `C` and produces the last result `O`.
///
/// The public builder selects input, model work, and finalization independently.
/// The chain retains preflight validation and named-output declarations across appended actions.
/// The private Step adapter applies the wiring's bindings, routing, and trace template.
pub(super) struct ActionChain<C, O> {
    run: Arc<RunAction<C, O>>,
    validate: Arc<ValidateAction>,
    pub(super) names: Vec<String>,
    pub(super) configuration: Result<ActionPlan, String>,
}

impl<C, O> Clone for ActionChain<C, O> {
    fn clone(&self) -> Self {
        Self {
            run: self.run.clone(),
            validate: self.validate.clone(),
            names: self.names.clone(),
            configuration: self.configuration.clone(),
        }
    }
}

impl<C: 'static, O: 'static> ActionChain<C, O> {
    pub(super) fn run(
        &self, context: &C, updates: &StateUpdates, response: Option<&ModelResponse>,
        proposals: &Map<String, JsonValue>, results: &mut Map<String, JsonValue>,
    ) -> Result<O, FlowError> {
        (self.run)(context, updates, response, proposals, results)
    }

    pub(super) fn validate(&self, scope: &Scope, model: Option<&ModelTemplate>) -> Result<(), FlowError> {
        (self.validate)(scope, model)
    }

    /// Executes an application operation during finalize, without calling a model.
    pub(super) fn operation(operation: impl Fn(&C) -> Result<O, String> + Send + Sync + 'static) -> Self {
        Self {
            run: Arc::new(move |context, _, _, _, _| operation(context).map_err(Into::into)),
            validate: Arc::new(|_, _| Ok(())),
            names: vec![],
            configuration: Err("Rust operation has no JSON configuration; use operation_with_config".into()),
        }
    }

    /// Appends an action after this chain. The previous result becomes its input; an error stops
    /// execution before the next callback. Callbacks share the same prepared context.
    pub(super) fn append<R: 'static>(
        self, process: impl Fn(&ActionContext<'_, C>, O) -> Result<R, String> + Send + Sync + 'static,
    ) -> ActionChain<C, R> {
        ActionChain {
            run: Arc::new(move |context, updates, response, proposals, results| {
                let previous = (self.run)(context, updates, response, proposals, results)?;
                process(
                    &ActionContext::new(context, response, results).with_proposals(proposals),
                    previous,
                )
                .map_err(Into::into)
            }),
            validate: self.validate,
            names: self.names,
            configuration: Err("Rust action has no JSON configuration; use action_with_config".into()),
        }
    }
}

impl<C: 'static, O: Serialize + 'static> ActionChain<C, O> {
    pub(super) fn record(self, name: String) -> Self {
        let mut names = self.names;
        names.push(name.clone());
        let configuration = self.configuration.map(|mut plan| {
            if let Some(action) = plan.actions.last_mut() {
                action.result = Some(name.clone());
            }
            plan
        });
        Self {
            run: Arc::new(move |context, updates, response, proposals, results| {
                let output = (self.run)(context, updates, response, proposals, results)?;
                let saved =
                    serde_json::to_value(&output).map_err(|error| format!("encode action result {name:?}: {error}"))?;
                results.insert(name.clone(), saved);
                Ok(output)
            }),
            validate: self.validate,
            names,
            configuration,
        }
    }
}

impl<C: Clone + 'static> ActionChain<C, C> {
    /// Uses context as the result, requiring no model or custom processing callback.
    pub(super) fn passthrough() -> Self {
        let mut chain = Self::operation(|context: &C| Ok(context.clone()));
        chain.configuration = Ok(ActionPlan {
            input: ActionInput::Context,
            actions: vec![],
        });
        chain
    }
}

impl<C: 'static, O: Value + Clone> ActionChain<C, O> {
    /// Selects a typed field from the model's proposed State updates for finalization processing.
    /// The field must be declared in State with type `O`; a missing proposed replacement is an error.
    pub(super) fn proposed(field: impl Into<String>) -> Self {
        let field = field.into();
        let check_field = field.clone();
        let configuration = Ok(ActionPlan {
            input: ActionInput::Proposed { field: field.clone() },
            actions: vec![],
        });
        Self {
            run: Arc::new(move |_, updates, _, _, _| {
                updates
                    .get::<O>(&field)
                    .cloned()
                    .ok_or_else(|| format!("missing or incorrectly typed proposed State field {field}").into())
            }),
            validate: Arc::new(move |scope, model| {
                if !model.is_some_and(|model| {
                    model
                        .state_update_criteria
                        .iter()
                        .any(|(field, _)| field == &check_field)
                }) {
                    return Err(format!("model must declare proposed State field {check_field}").into());
                }
                scope
                    .state()
                    .get::<O>(&check_field)
                    .ok_or_else(|| format!("missing or incorrectly typed State field {check_field}"))?;
                Ok(())
            }),
            names: vec![],
            configuration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lyquid_test::test;
    use serde_json::json;

    #[test]
    fn every_action_can_read_the_original_response_and_named_outputs() {
        let response = ModelResponse {
            text: Some("original text".into()),
            finish_reason: Some(lyquid_llm::FinishReason::Stop),
            usage: Some(lyquid_llm::Usage {
                input_tokens: Some(2),
                output_tokens: Some(3),
                total_tokens: Some(5),
            }),
            web_search_used: true,
            sources: vec!["https://example.com/source".into()],
            raw_json: json!({"provider": "payload"}),
            http: lyquid::http::Response {
                status: 200,
                headers: vec![],
                body: b"body".to_vec(),
            },
        };
        let expected = response.clone();
        let chain = ActionChain::passthrough()
            .append(|_: &ActionContext<'_, JsonValue>, _| Ok("unrelated first action"))
            .append(|context, _| {
                assert_eq!(context.model_response().unwrap().text.as_deref(), Some("original text"));
                Ok(json!({"answer": 42}))
            })
            .record("formatted".into())
            .append(|_, _| Ok(false))
            .append(move |context, previous| {
                assert!(!previous);
                assert_eq!(context.model_response(), Some(&expected));
                assert_eq!(context.result("formatted"), Some(&json!({"answer": 42})));
                Ok(())
            });
        let mut results = Map::new();
        chain
            .run(
                &json!({}),
                &StateUpdates::default(),
                Some(&response),
                &Map::new(),
                &mut results,
            )
            .unwrap();
        assert_eq!(results["formatted"], json!({"answer": 42}));
        let serialized = crate::context::model_response_json(&response);
        assert_eq!(serialized["usage"]["total_tokens"], 5);
        assert_eq!(serialized["sources"], json!(["https://example.com/source"]));
        assert_eq!(serialized["raw_json"], json!({"provider": "payload"}));
        assert_eq!(serialized["http"]["body"], json!([98, 111, 100, 121]));
        assert_eq!(serialized["finish_reason"], "stop");
    }
}
