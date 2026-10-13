//! The authoring interface for data wiring, phase selection, and typed finalization.

use std::collections::BTreeMap;
use std::sync::Arc;

use lyquid_flow::{FlowError, InputSpec, ModelTemplate, Scope, StepId, Value};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use tera::Tera;

use crate::action::ActionChain;
use crate::step::{ConfiguredStep, InputFactory};
use crate::{
    ActionConfiguration, ActionContext, Binding, BindingTarget, CallbackConfiguration, DataArgument,
    InputConfiguration, ModelOutput, NextCase, NextStep, Presence, StepConfiguration, StepData, StepWiring,
    ValueSource,
};

type PrepareContext<I, C> = dyn Fn(I) -> Result<C, String> + Send + Sync;

/// Builds an ordinary Flow Step from optional input/model components and ordered finalization callbacks.
///
/// Attach Flow's `InputSpec` with `with_input`, a `ModelTemplate` with `with_model`, and ordinary Rust
/// functions with `action`. Configure bindings, routing, and the trace in the same chain, then call
/// `build` to obtain a Step. Omitted components skip their optional work; Flow validates and commits.
///
/// `C` is the prepared context, `O` the finalization result, and `I` the decoded binding input
/// (normally `C`). Types are usually inferred from callbacks. Hosts can save and load wiring through
/// `wiring` and `with_wiring`; component selection and callbacks remain on the builder.
pub struct StepBuilder<C = JsonValue, O = C, I = C> {
    wiring: StepWiring,
    input: Option<Arc<InputFactory>>,
    model: Option<ModelTemplate>,
    prepare: Arc<PrepareContext<I, C>>,
    action: ActionChain<C, O>,
    input_configuration: Result<Option<InputConfiguration>, String>,
    export_context: Result<(), String>,
    data: StepData,
    data_errors: Vec<String>,
    model_codecs: BTreeMap<String, crate::data::ModelCodec>,
}

impl<C, O, I> Clone for StepBuilder<C, O, I> {
    fn clone(&self) -> Self {
        Self {
            wiring: self.wiring.clone(),
            input: self.input.clone(),
            model: self.model.clone(),
            prepare: self.prepare.clone(),
            action: self.action.clone(),
            input_configuration: self.input_configuration.clone(),
            export_context: self.export_context.clone(),
            data: self.data.clone(),
            data_errors: self.data_errors.clone(),
            model_codecs: self.model_codecs.clone(),
        }
    }
}

impl StepBuilder {
    /// Starts with JSON context pass-through, no input/model, and root completion.
    pub fn new() -> Self {
        Self::from_action(ActionChain::passthrough())
    }
}

impl Default for StepBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: 'static, O: 'static> StepBuilder<C, O> {
    fn from_action(action: ActionChain<C, O>) -> Self {
        Self {
            wiring: StepWiring {
                description: "Step".into(),
                bindings: vec![],
                next: NextStep::Fixed { next: None },
                summary: "Step".into(),
            },
            input: None,
            model: None,
            prepare: Arc::new(Ok),
            action,
            input_configuration: Ok(None),
            export_context: Ok(()),
            data: StepData::default(),
            data_errors: vec![],
            model_codecs: BTreeMap::new(),
        }
    }

    /// Starts with an operation executed only during finalize.
    pub fn operation(operation: impl Fn(&C) -> Result<O, String> + Send + Sync + 'static) -> Self {
        Self::from_action(ActionChain::operation(operation))
    }

    /// Starts with a typed Rust operation and an explicit configuration reference for JSON export.
    pub fn operation_with_config<S: Serialize + Send + Sync + 'static>(
        name: impl Into<String>, settings: S, operation: impl Fn(&C, &S) -> Result<O, String> + Send + Sync + 'static,
    ) -> Self {
        let configuration = CallbackConfiguration::new(name, &settings).map(|callback| crate::ActionPlan {
            input: crate::ActionInput::Context,
            actions: vec![ActionConfiguration { callback, result: None }],
        });
        let mut builder = Self::operation(move |context| operation(context, &settings));
        builder.action.configuration = configuration;
        builder
    }
}

impl<C: 'static, O: Value + Clone> StepBuilder<C, O> {
    /// Starts by selecting one typed proposed State replacement during finalize.
    pub fn proposed(field: impl Into<String>) -> Self {
        Self::from_action(ActionChain::proposed(field))
    }
}

impl<C: 'static, O: 'static, I: 'static> StepBuilder<C, O, I> {
    /// Declares a required Step-local argument, exposed as `context.<name>`.
    pub fn data<T: JsonSchema>(self, name: impl Into<String>) -> Self {
        self.data_schema(name, crate::data::schema::<T>(false), Presence::Required)
    }

    pub fn optional_data<T: JsonSchema>(self, name: impl Into<String>) -> Self {
        self.data_schema(name, crate::data::schema::<T>(false), Presence::Optional)
    }

    pub fn data_default<T: JsonSchema + Serialize>(mut self, name: impl Into<String>, value: T) -> Self {
        match serde_json::to_value(value) {
            Ok(value) => self.data_schema(name, crate::data::schema::<T>(false), Presence::Default { value }),
            Err(error) => {
                self.data_errors.push(format!("encode data default: {error}"));
                self
            }
        }
    }

    /// Declares a JSON-shaped argument alongside ordinary native actions; this is not a JSON loader.
    pub fn data_schema(mut self, name: impl Into<String>, schema: JsonValue, presence: Presence) -> Self {
        let name = name.into();
        if self
            .data
            .arguments
            .insert(name.clone(), DataArgument { schema, presence })
            .is_some()
        {
            self.data_errors.push(format!("duplicate data argument {name:?}"));
        }
        self
    }

    /// Describes the serialized final result, checked before any turn writes commit.
    pub fn result<T: JsonSchema>(mut self) -> Self {
        self.data.result = Some(crate::data::schema::<T>(true));
        self
    }

    /// Declares a logical proposal. Its State destination is the final-result binding at `pointer`.
    /// Actions read it by `name` using `ActionContext::proposed`.
    pub fn model_output<T: JsonSchema + Value + Serialize>(
        mut self, name: impl Into<String>, pointer: impl Into<String>, criterion: impl Into<String>,
    ) -> Self {
        let name = name.into();
        self.model_codecs.insert(
            name.clone(),
            Arc::new(|scope, updates, field| {
                let value = match updates {
                    Some(updates) => updates.get::<T>(field),
                    None => scope.state().get::<T>(field),
                }
                .ok_or_else(|| format!("missing or incorrectly typed model output State field {field:?}"))?;
                serde_json::to_value(value).map_err(|e| format!("encode model output {field:?}: {e}"))
            }),
        );
        let output = ModelOutput {
            schema: crate::data::schema::<T>(false),
            pointer: pointer.into(),
            criterion: criterion.into(),
        };
        if self.data.model_outputs.insert(name.clone(), output).is_some() {
            self.data_errors.push(format!("duplicate model output {name:?}"));
        }
        self
    }

    /// Inspect a reusable builder without resolving bindings or exporting opaque callbacks.
    pub fn data_contract(&self) -> &StepData {
        &self.data
    }

    pub fn bind_data(self, name: impl Into<String>, source: ValueSource) -> Self {
        self.bind(source, BindingTarget::Context { name: name.into() })
    }

    /// Exports configuration without executing Rust callbacks or constructing a runtime.
    /// Opaque callbacks fail export; native execution remains available through `build`.
    pub fn configuration(&self) -> Result<StepConfiguration, String> {
        self.validate(false)?;
        self.export_configuration(self.configured_model()?.as_ref())
    }

    fn export_configuration(&self, model: Option<&ModelTemplate>) -> Result<StepConfiguration, String> {
        self.export_context.clone()?;
        Ok(StepConfiguration {
            version: 1,
            wiring: self.wiring.clone(),
            data: self.data.clone(),
            input: self.input_configuration.clone()?,
            model: model.map(Into::into),
            finalization: self.action.configuration.clone()?,
        })
    }

    pub fn to_json(&self) -> Result<String, String> {
        self.configuration()?.to_json()
    }

    fn configured_model(&self) -> Result<Option<ModelTemplate>, String> {
        self.model
            .clone()
            .map(|mut model| {
                model.allow_restore &= matches!(self.wiring.next, NextStep::Proposed);
                for (name, output) in &self.data.model_outputs {
                    // Reusable builders can export unresolved declarations; build requires every binding.
                    let Ok(field) = self.data.model_field(&self.wiring, name) else {
                        continue
                    };
                    if model
                        .state_update_criteria
                        .iter()
                        .any(|(existing, _)| existing == field)
                    {
                        return Err(format!("duplicate model State destination {field:?}"));
                    }
                    model
                        .state_update_criteria
                        .push((field.into(), output.criterion.clone()));
                }
                Ok(model)
            })
            .transpose()
    }

    /// Changes the human-readable description. Configure the trace separately with `summary`.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.wiring.description = description.into();
        self
    }

    /// Exports the current serializable wiring, before Scope-dependent validation.
    pub fn wiring(&self) -> &StepWiring {
        &self.wiring
    }

    /// Imports/replaces wiring while retaining behavior, context preparation, input, and model.
    pub fn with_wiring(mut self, wiring: StepWiring) -> Self {
        self.wiring = wiring;
        self
    }

    /// Decodes bindings as `J` and prepares `C`. This must be pure: model preflight and finalize
    /// both evaluate it. `C` itself need not implement Deserialize when this method is used.
    pub fn with_context<J: 'static>(
        self, prepare: impl Fn(J) -> Result<C, String> + Send + Sync + 'static,
    ) -> StepBuilder<C, O, J> {
        StepBuilder {
            wiring: self.wiring,
            input: self.input,
            model: self.model,
            prepare: Arc::new(prepare),
            action: self.action,
            input_configuration: self.input_configuration,
            export_context: Err("Rust context preparation has no JSON configuration".into()),
            data: self.data,
            data_errors: self.data_errors,
            model_codecs: self.model_codecs,
        }
    }

    /// Appends a flat source-to-target binding.
    pub fn bind(mut self, from: ValueSource, to: BindingTarget) -> Self {
        self.wiring.bindings.push(Binding { from, to });
        self
    }

    pub fn bind_state(self, name: impl Into<String>, field: impl Into<String>) -> Self {
        self.bind(
            ValueSource::State { field: field.into() },
            BindingTarget::Context { name: name.into() },
        )
    }

    pub fn bind_input(self, name: impl Into<String>, input: impl Into<String>) -> Self {
        self.bind(
            ValueSource::Input { name: input.into() },
            BindingTarget::Context { name: name.into() },
        )
    }

    pub fn bind_execution_id(self, name: impl Into<String>) -> Self {
        self.bind(ValueSource::ExecutionId, BindingTarget::Context { name: name.into() })
    }

    /// Stages a State replacement from a JSON Pointer in the finalization result.
    pub fn update(self, field: impl Into<String>, pointer: impl Into<String>) -> Self {
        self.update_from(
            field,
            ValueSource::Result {
                pointer: pointer.into(),
            },
        )
    }

    pub fn update_from(self, field: impl Into<String>, source: ValueSource) -> Self {
        self.bind(source, BindingTarget::State { field: field.into() })
    }

    pub fn constant(self, field: impl Into<String>, value: impl Into<JsonValue>) -> Self {
        self.update_from(field, ValueSource::Constant { value: value.into() })
    }

    /// Selects a fixed successor. Model restore proposals are not permitted.
    pub fn next(mut self, next: impl Into<StepId>) -> Self {
        self.wiring.next = NextStep::Fixed {
            next: Some(next.into()),
        };
        self
    }

    /// Completes a root Flow. Mounted Flows must instead select a declared exit.
    /// Model restore proposals are not permitted.
    pub fn complete(mut self) -> Self {
        self.wiring.next = NextStep::Fixed { next: None };
        self
    }

    /// Selects a successor from the action result. Model restore proposals are not permitted.
    pub fn route_by<K: Into<String>, N: Into<StepId>>(
        mut self, pointer: impl Into<String>, cases: impl IntoIterator<Item = (K, N)>,
    ) -> Self {
        self.wiring.next = NextStep::Result {
            pointer: pointer.into(),
            cases: cases
                .into_iter()
                .map(|(value, next)| NextCase {
                    value: value.into(),
                    next: Some(next.into()),
                })
                .collect(),
        };
        self
    }

    /// Preserves model routing, including restores when allowed by the attached model template.
    pub fn proposed_next(mut self) -> Self {
        self.wiring.next = NextStep::Proposed;
        self
    }

    pub fn summary(mut self, template: impl Into<String>) -> Self {
        self.wiring.summary = template.into();
        self
    }

    /// Attaches an `InputSpec` built with Flow's field, validation, and layout builders.
    /// Specs can also be deserialized from JSON; their fields retain schema-validated JSON values.
    /// Rust-built specs keep their typed decoders. Reusable functions returning a spec are optional.
    pub fn with_input(self, input: InputSpec) -> Self {
        let configuration = InputConfiguration::Static {
            specification: input.clone(),
        };
        let mut builder = self.with_input_factory(move |_| input.clone());
        builder.input_configuration = Ok(Some(configuration));
        builder
    }

    /// Builds presentation from read-only Scope. Called for presentation and again during model
    /// preflight and finalization; the callback must be pure and deterministic.
    pub fn with_input_factory(self, input: impl Fn(&Scope) -> InputSpec + Send + Sync + 'static) -> Self {
        self.with_fallible_input_factory(move |scope| Ok(input(scope)))
    }

    /// Pure fallible presentation, also called during model preflight and finalization. Failures
    /// prevent model/action execution and are reported by finalize because Flow's existing
    /// input/model-template hooks cannot return errors.
    pub fn with_fallible_input_factory(
        mut self, input: impl Fn(&Scope) -> Result<InputSpec, FlowError> + Send + Sync + 'static,
    ) -> Self {
        self.input = Some(Arc::new(move |scope, _| input(scope)));
        self.input_configuration =
            Err("Rust input factory has no JSON configuration; use with_input_factory_config".into());
        self
    }

    /// Retains a pure Rust input factory and exports its explicit name/settings. The callback uses
    /// the same settings that are serialized. JSON consumers must supply their own implementation.
    pub fn with_input_factory_config<S: Serialize + Send + Sync + 'static>(
        self, name: impl Into<String>, settings: S,
        factory: impl Fn(&Scope, &S) -> Result<InputSpec, FlowError> + Send + Sync + 'static,
    ) -> Self {
        let configuration =
            CallbackConfiguration::new(name, &settings).map(|callback| Some(InputConfiguration::Factory { callback }));
        let mut builder = self.with_fallible_input_factory(move |scope| factory(scope, &settings));
        builder.input_configuration = configuration;
        builder
    }

    pub fn with_model(mut self, template: ModelTemplate) -> Self {
        self.model = Some(template);
        self
    }

    /// Pure input presentation using bound data arguments without concrete State names or Scope.
    /// Arguments bound from interactive Input are unavailable before its submission.
    pub fn with_data_input_factory_config<S: Serialize + Send + Sync + 'static>(
        mut self, name: impl Into<String>, settings: S,
        factory: impl Fn(&JsonValue, &S) -> Result<InputSpec, FlowError> + Send + Sync + 'static,
    ) -> Self {
        self.input_configuration = CallbackConfiguration::new(name, &settings)
            .map(|callback| Some(InputConfiguration::DataFactory { callback }));
        self.input = Some(Arc::new(move |_, data| factory(data, &settings)));
        self
    }
    /// Appends an action and retains its serializable output in temporary context under `name`.
    /// Later actions read it with `context.result(name)`; bindings use `ValueSource::ActionResult`.
    pub fn action_named<R: Serialize + 'static>(
        self, name: impl Into<String>,
        process: impl Fn(&ActionContext<'_, C>, O) -> Result<R, String> + Send + Sync + 'static,
    ) -> StepBuilder<C, R, I> {
        let mut builder = self.action(process);
        builder.action = builder.action.record(name.into());
        builder
    }

    /// Appends an ordinary Rust action and retains an explicit reference/settings for JSON export.
    /// There is no registry lookup during native execution, and the callback is never serialized.
    pub fn action_with_config<R: 'static, S: Serialize + Send + Sync + 'static>(
        self, name: impl Into<String>, settings: S,
        process: impl Fn(&ActionContext<'_, C>, O, &S) -> Result<R, String> + Send + Sync + 'static,
    ) -> StepBuilder<C, R, I> {
        let configuration = self.action.configuration.clone().and_then(|mut plan| {
            plan.actions.push(ActionConfiguration {
                callback: CallbackConfiguration::new(name, &settings)?,
                result: None,
            });
            Ok(plan)
        });
        let mut builder = self.action(move |context, previous| process(context, previous, &settings));
        builder.action.configuration = configuration;
        builder
    }

    pub fn action_named_with_config<R: Serialize + 'static, S: Serialize + Send + Sync + 'static>(
        self, result: impl Into<String>, name: impl Into<String>, settings: S,
        process: impl Fn(&ActionContext<'_, C>, O, &S) -> Result<R, String> + Send + Sync + 'static,
    ) -> StepBuilder<C, R, I> {
        let mut builder = self.action_with_config(name, settings, process);
        builder.action = builder.action.record(result.into());
        builder
    }

    /// Appends a finalization action in declaration order. It receives the same prepared context
    /// and the previous action's result. An error stops the chain and rejects the entire turn.
    /// Result bindings and result-based routing use the last result. Named outputs and the model
    /// response remain available to other bindings and the trace after all actions succeed.
    pub fn action<R: 'static>(
        self, process: impl Fn(&ActionContext<'_, C>, O) -> Result<R, String> + Send + Sync + 'static,
    ) -> StepBuilder<C, R, I> {
        StepBuilder {
            wiring: self.wiring,
            input: self.input,
            model: self.model,
            prepare: self.prepare,
            action: self.action.append(process),
            input_configuration: self.input_configuration,
            export_context: self.export_context,
            data: self.data,
            data_errors: self.data_errors,
            model_codecs: self.model_codecs,
        }
    }

    fn validate(&self, require_bound: bool) -> Result<(), String> {
        validate_wiring(&self.wiring, self.model.is_some())?;
        if let Some(error) = self.data_errors.first() {
            return Err(error.clone())
        }
        self.data.validate(&self.wiring, require_bound)?;
        if let Ok(Some(InputConfiguration::Static { specification })) = &self.input_configuration {
            self.data.validate_input_bindings(&self.wiring, specification)?;
        }
        if !self.data.model_outputs.is_empty() && self.model.is_none() {
            return Err("logical model outputs require a model template".into());
        }
        if let Some(model) = &self.model {
            let mut tera = Tera::default();
            for value in std::iter::once(&model.step_goal)
                .chain(model.next_step_criteria.iter().map(|(_, text)| text))
                .chain(model.state_update_criteria.iter().map(|(_, text)| text))
                .chain(self.data.model_outputs.values().map(|output| &output.criterion))
            {
                tera.add_raw_template("model", value)
                    .map_err(|error| format!("parse model template: {error}"))?;
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for name in &self.action.names {
            if name.trim().is_empty() || !names.insert(name) {
                return Err(format!("action result name must be nonblank and unique: {name:?}"));
            }
        }
        for binding in &self.wiring.bindings {
            if let ValueSource::ActionResult { action, .. } = binding.from.root() &&
                !names.contains(action)
            {
                return Err(format!("unknown action result {action:?}"));
            }
            if matches!(binding.from.root(), ValueSource::ModelResponse { .. }) && self.model.is_none() {
                return Err("model response bindings require a model template".into());
            }
        }
        Ok(())
    }
}

impl<C: Serialize + 'static, O: Serialize + 'static, I: 'static> StepBuilder<C, O, I> {
    /// Checks static wiring and builds a cloneable ordinary Step. Does not execute callbacks.
    /// State codecs, input values, prepared context, and graph destinations are checked at runtime
    /// before model/action effects, when a Scope is available.
    pub fn build(self) -> Result<ConfiguredStep<C, O>, String>
    where
        I: DeserializeOwned,
    {
        self.validate(true)?;
        let model = self.configured_model()?;
        let configuration = self.export_configuration(model.as_ref());
        Ok(ConfiguredStep {
            configuration,
            wiring: self.wiring,
            input: self.input,
            model,
            data: self.data,
            model_codecs: self.model_codecs,
            action: self.action,
            context: Arc::new(move |value| {
                let input = serde_json::from_value(value).map_err(|error| format!("decode Step context: {error}"))?;
                (self.prepare)(input).map_err(Into::into)
            }),
        })
    }
}

fn validate_wiring(wiring: &StepWiring, has_model: bool) -> Result<(), String> {
    Tera::default()
        .add_raw_template("summary", &wiring.summary)
        .map_err(|error| format!("parse Step summary: {error}"))?;
    for (index, binding) in wiring.bindings.iter().enumerate() {
        validate_binding(binding)?;
        if wiring.bindings[..index].iter().any(|other| other.to == binding.to) {
            return Err(format!("duplicate binding target {:?}", binding.to));
        }
    }
    match &wiring.next {
        NextStep::Proposed if !has_model => return Err("proposed routing requires a model template".into()),
        NextStep::Result { pointer, cases } => {
            validate_pointer(pointer).map_err(|error| format!("route binding: {error}"))?;
            if cases.is_empty() {
                return Err("result routing requires at least one case".into());
            }
            for (index, case) in cases.iter().enumerate() {
                if cases[..index].iter().any(|other| other.value == case.value) {
                    return Err(format!("duplicate route case {:?}", case.value));
                }
            }
        }
        _ => (),
    }
    Ok(())
}

fn validate_binding(binding: &Binding) -> Result<(), String> {
    let name = match &binding.to {
        BindingTarget::Context { name } => name,
        BindingTarget::State { field } => field,
    };
    if name.trim().is_empty() {
        return Err("binding target must be nonblank".into());
    }
    if matches!(binding.to, BindingTarget::Context { .. }) &&
        matches!(
            binding.from.root(),
            ValueSource::Context { .. } |
                ValueSource::Result { .. } |
                ValueSource::ModelResponse { .. } |
                ValueSource::ActionResult { .. }
        )
    {
        return Err("Context targets only accept State, Input, ExecutionId, or Constant sources".into());
    }
    let mut source = &binding.from;
    while let ValueSource::Select { source: inner, pointer } = source {
        validate_pointer(pointer)?;
        source = inner;
    }
    if let ValueSource::Result { pointer } |
    ValueSource::ModelResponse { pointer } |
    ValueSource::ActionResult { pointer, .. } = source
    {
        validate_pointer(pointer).map_err(|error| format!("result binding: {error}"))?;
    }
    Ok(())
}

pub(crate) fn validate_pointer(pointer: &str) -> Result<(), String> {
    let invalid = || format!("{pointer:?} must be a JSON Pointer");
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return Err(invalid());
    }
    let mut chars = pointer.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lyquid_test::test;

    use super::*;

    #[test]
    fn wiring_round_trips_without_an_input_or_runtime_format() {
        let wiring = StepBuilder::new()
            .description("Count")
            .next("done")
            .bind_input("count", "answer")
            .update("count", "")
            .constant("message", "")
            .summary("Count {{ result }}")
            .wiring()
            .clone();
        let encoded = serde_json::to_value(&wiring).unwrap();
        let decoded: StepWiring = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
        assert!(encoded.get("input").is_none());
        assert!(encoded.get("context").is_none());
        assert!(encoded.get("updates").is_none());
        assert_eq!(
            encoded["bindings"][0],
            serde_json::json!({
                "from": {"kind": "input", "name": "answer"},
                "to": {"kind": "context", "name": "count"},
            })
        );
        assert!(
            serde_json::from_value::<StepWiring>(serde_json::json!({
                "unexpected": true,
                "description": "Count",
                "bindings": [],
                "next": { "kind": "fixed", "next": "done" },
                "summary": "Count"
            }))
            .is_err()
        );
    }

    #[test]
    fn every_source_target_pair_has_an_explicit_phase_contract() {
        for from in [
            ValueSource::State { field: "value".into() },
            ValueSource::Input { name: "value".into() },
            ValueSource::ExecutionId,
            ValueSource::Constant {
                value: serde_json::json!({"value": 7}),
            },
            ValueSource::Context { name: "value".into() },
            ValueSource::Result {
                pointer: "/value".into(),
            },
            ValueSource::ModelResponse {
                pointer: "/text".into(),
            },
            ValueSource::ActionResult {
                action: "saved".into(),
                pointer: "/value".into(),
            },
        ] {
            for to in [
                BindingTarget::Context { name: "value".into() },
                BindingTarget::State { field: "value".into() },
            ] {
                let available = matches!(to, BindingTarget::State { .. }) ||
                    !matches!(
                        from,
                        ValueSource::Context { .. } |
                            ValueSource::Result { .. } |
                            ValueSource::ModelResponse { .. } |
                            ValueSource::ActionResult { .. }
                    );
                let binding = Binding { from: from.clone(), to };
                assert_eq!(validate_binding(&binding).is_ok(), available, "{binding:?}");
                assert_eq!(
                    serde_json::from_value::<Binding>(serde_json::to_value(&binding).unwrap()).unwrap(),
                    binding
                );
            }
        }
        for pointer in ["invalid", "/bad~", "/bad~2"] {
            let binding = Binding {
                from: ValueSource::Result {
                    pointer: pointer.into(),
                },
                to: BindingTarget::State { field: "value".into() },
            };
            assert!(validate_binding(&binding).is_err());
        }
        for pointer in ["", "/a~1b/~0key", "/items/0"] {
            let binding = Binding {
                from: ValueSource::Result {
                    pointer: pointer.into(),
                },
                to: BindingTarget::State { field: "value".into() },
            };
            assert!(validate_binding(&binding).is_ok());
        }
    }
}
