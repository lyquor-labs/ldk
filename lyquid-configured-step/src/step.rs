//! Adapts a wiring and typed action to the ordinary Flow Step lifecycle.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use lyquid_flow::{
    FlowError, InputSpec, ModelTemplate, Scope, StateNamespace, StateUpdates, Step, StepId, TemplateSpec, TraceSummary,
    TurnProposal, Value,
};
use serde::Serialize;
use serde_json::{Map, Value as JsonValue};
use tera::{Context, Tera};

use crate::action::ActionChain;
use crate::context::model_response_json;
use crate::{BindingTarget, NextStep, Presence, StepConfiguration, StepData, StepWiring, ValueSource};

pub(super) type ReadContext<C> = dyn Fn(JsonValue) -> Result<C, FlowError> + Send + Sync;
pub(super) type InputFactory = dyn Fn(&Scope, &JsonValue) -> Result<InputSpec, FlowError> + Send + Sync;

/// An ordinary Flow Step composed from wiring and optional input, model, and processing units.
/// Input uses `InputSpec`; model work uses `ModelTemplate`; `ActionChain` runs during finalize.
/// Flow retains the existing input → model → finalize → validate/commit lifecycle.
pub struct ConfiguredStep<C, O> {
    pub(super) wiring: StepWiring,
    pub(super) input: Option<Arc<InputFactory>>,
    pub(super) model: Option<ModelTemplate>,
    pub(super) context: Arc<ReadContext<C>>,
    pub(super) action: ActionChain<C, O>,
    pub(super) configuration: Result<StepConfiguration, String>,
    pub(super) data: StepData,
    pub(super) model_codecs: BTreeMap<String, crate::data::ModelCodec>,
}

impl<C, O> ConfiguredStep<C, O> {
    pub fn configuration(&self) -> Result<&StepConfiguration, String> {
        self.configuration.as_ref().map_err(Clone::clone)
    }

    pub fn to_json(&self) -> Result<String, String> {
        self.configuration()?.to_json()
    }

    pub fn data_contract(&self) -> &StepData {
        &self.data
    }
}

impl<C, O> Clone for ConfiguredStep<C, O> {
    fn clone(&self) -> Self {
        Self {
            wiring: self.wiring.clone(),
            input: self.input.clone(),
            model: self.model.clone(),
            context: self.context.clone(),
            action: self.action.clone(),
            configuration: self.configuration.clone(),
            data: self.data.clone(),
            model_codecs: self.model_codecs.clone(),
        }
    }
}

impl<C: Serialize + 'static, O: Serialize + 'static> ConfiguredStep<C, O> {
    fn validate_wiring(&self, scope: &Scope) -> Result<(), FlowError> {
        match &self.wiring.next {
            NextStep::Fixed { next } => scope.validate_next(next)?,
            NextStep::Result { cases, .. } => {
                for case in cases {
                    scope.validate_next(&case.next)?;
                }
            }
            NextStep::Proposed => (),
        }
        for binding in &self.wiring.bindings {
            if let BindingTarget::State { field } = &binding.to {
                // Check destinations even when their values are only available after preparation/actions.
                if scope.state().get_value(field).is_none() {
                    return Err(format!("unknown State update field {field}").into());
                }
                if let Some(value) = read_source(&binding.from, scope)? {
                    decode_update(scope, field, &value)?;
                } else if matches!(
                    binding.from.root(),
                    ValueSource::Input { .. } |
                        ValueSource::InputOr { .. } |
                        ValueSource::State { .. } |
                        ValueSource::ExecutionId |
                        ValueSource::Constant { .. }
                ) {
                    return Err(format!("missing binding source for State field {field:?}").into());
                }
            }
        }
        for name in self.data.model_outputs.keys() {
            let field = self.data.model_field(&self.wiring, name)?;
            // The current State value need only have the native destination type. Output constraints
            // apply to the proposed value during finalization, not to an initial placeholder.
            (self.model_codecs[name])(scope, None, field)?;
        }
        Ok(())
    }

    fn read_bindings(&self, scope: &Scope, presentation: bool) -> Result<JsonValue, FlowError> {
        let mut values = Map::new();
        let mut pending = BTreeSet::new();
        for binding in &self.wiring.bindings {
            let BindingTarget::Context { name } = &binding.to else {
                continue
            };
            if presentation &&
                matches!(
                    binding.from.root(),
                    ValueSource::Input { .. } | ValueSource::InputOr { .. }
                )
            {
                pending.insert(name.as_str());
                continue;
            }
            match read_source(&binding.from, scope)? {
                Some(value) => {
                    values.insert(name.clone(), value);
                }
                None if self.data.arguments.contains_key(name) => (),
                None => return Err(format!("source unavailable before action for context binding {name}").into()),
            }
        }
        for (name, argument) in &self.data.arguments {
            if pending.contains(name.as_str()) {
                continue;
            }
            if !values.contains_key(name) {
                match &argument.presence {
                    Presence::Required => return Err(format!("missing required data argument {name:?}").into()),
                    Presence::Optional => continue,
                    Presence::Default { value } => {
                        values.insert(name.clone(), value.clone());
                    }
                }
            }
            lyquid_flow::validate_json_schema(&argument.schema, &values[name], &format!("argument {name}"))?;
        }
        Ok(JsonValue::Object(values))
    }

    fn input_spec(&self, scope: &Scope) -> Result<Option<InputSpec>, FlowError> {
        self.input
            .as_ref()
            .map(|input| input(scope, &self.read_bindings(scope, true)?))
            .transpose()
    }

    fn validate_context_updates(&self, scope: &Scope, context: &C) -> Result<(), FlowError> {
        let context = serde_json::to_value(context).map_err(|error| format!("encode Step context: {error}"))?;
        for binding in &self.wiring.bindings {
            let (ValueSource::Context { .. }, BindingTarget::State { field }) = (binding.from.root(), &binding.to)
            else {
                continue
            };
            let value = read_final_source(&binding.from, scope, &context, &JsonValue::Null, &None, &Map::new())?;
            decode_update(scope, field, &value)?;
        }
        Ok(())
    }

    fn finish(
        &self, scope: &Scope, context: &C, output: &O, results: &Map<String, JsonValue>,
        proposed_next: &Option<StepId>, updates: &StateUpdates,
    ) -> Result<(TurnProposal, TraceSummary), FlowError> {
        let output = serde_json::to_value(output).map_err(|error| format!("encode Step result: {error}"))?;
        if let Some(schema) = &self.data.result {
            lyquid_flow::validate_json_schema(schema, &output, "result")?;
        }
        let context = serde_json::to_value(context).map_err(|error| format!("encode Step context: {error}"))?;
        let model_response = scope.model_response().map(model_response_json);
        let next = match &self.wiring.next {
            NextStep::Proposed => proposed_next.clone(),
            NextStep::Fixed { next } => next.clone(),
            NextStep::Result { pointer, cases } => {
                let value = output
                    .pointer(pointer)
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| format!("Step result must contain a string route at {pointer:?}"))?;
                cases
                    .iter()
                    .find(|case| case.value == value)
                    .map(|case| case.next.clone())
                    .ok_or_else(|| format!("unknown result route {value:?}"))?
            }
        };
        // Declarative bindings revise the existing proposal just like an ordinary Step finalizer.
        let mut updates = updates.clone();
        for binding in &self.wiring.bindings {
            let BindingTarget::State { field } = &binding.to else {
                continue
            };
            let value = read_final_source(&binding.from, scope, &context, &output, &model_response, results)?;
            updates.set(field.clone(), Some(decode_update(scope, field, &value)?));
        }
        let mut template_context = Context::new();
        template_context.insert("state", &scope.state().to_json()?);
        template_context.insert("context", &context);
        template_context.insert("result", &output);
        template_context.insert("model_response", &model_response);
        template_context.insert("actions", results);
        let summary = Tera::one_off(&self.wiring.summary, &template_context, false)
            .map_err(|error| format!("render Step summary: {error}"))?;
        Ok((TurnProposal::Advance { next, updates }, TraceSummary::Summary(summary)))
    }
    fn prepare(&self, scope: &Scope) -> Result<C, FlowError> {
        self.input_spec(scope)?;
        self.validate_wiring(scope)?;
        let context = (self.context)(self.read_bindings(scope, false)?)?;
        self.validate_context_updates(scope, &context)?;
        self.action.validate(scope, self.model.as_ref())?;
        Ok(context)
    }
}

impl<C: Serialize + 'static, O: Serialize + 'static> Step for ConfiguredStep<C, O> {
    fn description(&self, _concise: bool) -> String {
        self.wiring.description.clone()
    }

    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        // prepare() propagates this error through the ordinary fallible finalize hook.
        self.input_spec(scope).ok().flatten()
    }

    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        // This hook cannot return an error. Failed preflight skips external work; the same pure
        // preparation reports the error through finalize. No shared Step cache is needed.
        if let Some(model) = &self.model &&
            self.prepare(scope).is_ok()
        {
            return TemplateSpec::Template(model.clone());
        }
        TemplateSpec::Skip(TurnProposal::Advance {
            next: match &self.wiring.next {
                NextStep::Fixed { next } => next.clone(),
                _ => None,
            },
            updates: StateUpdates::default(),
        })
    }

    fn model_context(&self, scope: &Scope) -> Result<JsonValue, FlowError> {
        serde_json::to_value(self.prepare(scope)?).map_err(|error| format!("encode Step model context: {error}").into())
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let TurnProposal::Advance { next, updates } = proposal else {
            if !self.model.as_ref().is_some_and(|model| model.allow_restore) {
                return Err("restore proposals are not permitted by the configured routing"
                    .to_owned()
                    .into());
            }
            // Scope validates and applies restores; no forward actions, bindings, or trace are needed.
            // The ordinary Step contract requires a summary, which Scope ignores for restores.
            return Ok(TraceSummary::Summary(String::new()));
        };
        let context = self.prepare(scope)?;
        let mut proposals = Map::new();
        for (name, output) in &self.data.model_outputs {
            let field = self.data.model_field(&self.wiring, name)?;
            let value = (self.model_codecs[name])(scope, Some(updates), field)?;
            lyquid_flow::validate_json_schema(&output.schema, &value, &format!("model output {name}"))?;
            proposals.insert(name.clone(), value);
        }
        let mut results = Map::new();
        let output = self
            .action
            .run(&context, updates, scope.model_response(), &proposals, &mut results)?;
        let (processed, summary) = self.finish(scope, &context, &output, &results, next, updates)?;
        *proposal = processed;
        Ok(summary)
    }
}

fn decode_update(scope: &Scope, field: &str, value: &JsonValue) -> Result<Box<dyn Value>, FlowError> {
    let destination = scope
        .state()
        .get_value(field)
        .ok_or_else(|| format!("unknown State update field {field}"))?;
    let decoded = destination
        .decode(&value.to_string())
        .map_err(|error| format!("invalid State update {field}: {error}"))?;
    if decoded.as_ref().type_id() != destination.type_id() {
        return Err(format!("invalid State update {field}: decoder returned a different concrete value type").into());
    }
    Ok(decoded)
}

fn read_source(source: &ValueSource, scope: &Scope) -> Result<Option<JsonValue>, FlowError> {
    Ok(Some(match source {
        ValueSource::Select { source, pointer } => {
            return Ok(read_source(source, scope)?.and_then(|value| value.pointer(pointer).cloned()));
        }
        ValueSource::Input { name } => match scope.get_value(StateNamespace::Input, name) {
            Some(value) => serde_json::from_str(&value.encode()).map_err(|error| error.to_string())?,
            None => return Ok(None),
        },
        ValueSource::InputOr { name, default } => match scope.get_value(StateNamespace::Input, name) {
            Some(value) => serde_json::from_str(&value.encode()).map_err(|error| error.to_string())?,
            None => default.clone(),
        },
        ValueSource::State { field } => {
            let value = scope
                .state()
                .get_value(field)
                .ok_or_else(|| format!("missing default source {field:?} for binding"))?;
            serde_json::from_str(&value.encode())
                .map_err(|error| format!("decode binding source {field:?}: {error}"))?
        }
        ValueSource::ExecutionId => JsonValue::String(scope.execution_id().to_string()),
        ValueSource::Constant { value } => value.clone(),
        ValueSource::Context { .. } |
        ValueSource::Result { .. } |
        ValueSource::ModelResponse { .. } |
        ValueSource::ActionResult { .. } => return Ok(None),
    }))
}

fn read_final_source(
    source: &ValueSource, scope: &Scope, context: &JsonValue, output: &JsonValue, response: &Option<JsonValue>,
    results: &Map<String, JsonValue>,
) -> Result<JsonValue, FlowError> {
    let selected = match source {
        ValueSource::Select { source, pointer } => {
            return read_final_source(source, scope, context, output, response, results)?
                .pointer(pointer)
                .cloned()
                .ok_or_else(|| format!("binding source is missing {pointer:?}").into());
        }
        ValueSource::Context { name } => {
            return context
                .get(name)
                .cloned()
                .ok_or_else(|| format!("Step context is missing {name:?}").into());
        }
        ValueSource::Result { pointer } => output.pointer(pointer),
        ValueSource::ModelResponse { pointer } => response.as_ref().and_then(|value| value.pointer(pointer)),
        ValueSource::ActionResult { action, pointer } => results.get(action).and_then(|value| value.pointer(pointer)),
        _ => return read_source(source, scope)?.ok_or_else(|| format!("missing binding source {source:?}").into()),
    };
    selected
        .cloned()
        .ok_or_else(|| format!("missing binding source {source:?}").into())
}
