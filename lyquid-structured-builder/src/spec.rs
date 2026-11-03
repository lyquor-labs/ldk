use std::collections::BTreeSet;
use std::sync::Arc;

use lyquid_flow::{BuildError, Diagnostic, Diagnostics, FlowError, Scope, StateNamespace, Step, StepId, Type};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tera::Tera;
use typed_builder::TypedBuilder;

use crate::StructuredStep;

/// Structured rules for an existing Step.
///
/// Construct directly, with the derived builder, or from JSON. All forms are validated by `with`.
/// Inputs, Output, and destination arguments are not yet applied during execution.
#[derive(Clone, Default, Deserialize, Serialize, TypedBuilder)]
#[builder(field_defaults(default))]
#[serde(default, deny_unknown_fields)]
pub struct StructuredSpec {
    /// Input parameter declarations.
    pub inputs: Vec<Input>,
    /// Optional output declaration.
    #[builder(setter(strip_option))]
    pub output: Option<Output>,
    /// Field updates applied after the native finalizer; model criteria require a native model template.
    /// References and criteria read the current committed State, without pending updates.
    pub state_updates: Vec<(String, ValueSpec)>,
    /// Replaces model next-Step choices and the final route when nonempty; empty preserves native routing.
    pub next: Vec<NextStep>,
}

/// One parameter in the Inputs section.
#[derive(Clone, Deserialize, Serialize, TypedBuilder)]
#[serde(deny_unknown_fields)]
pub struct Input {
    #[builder(setter(into))]
    pub name: String,
    #[builder(setter(into))]
    pub description: String,
    pub required: bool,
    pub ty: Type,
}

/// Declares the single value a Step produces.
#[derive(Clone, Deserialize, Serialize, TypedBuilder)]
#[serde(deny_unknown_fields)]
pub struct Output {
    #[builder(setter(into))]
    pub description: String,
    pub ty: Type,
    pub value: ValueSpec,
}

/// One candidate in the Next Step section.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NextStep {
    /// A local Step/exit, or root completion when `None`.
    pub next: Option<StepId>,
    pub description: String,
    /// Named input value specifications for the destination Step.
    #[serde(default)]
    pub inputs: Vec<(String, ValueSpec)>,
}

/// The three supported sources for a State update.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueSpec {
    Constant {
        value: Value,
    },
    /// Reads the current State (or submitted input), before this turn's updates are applied.
    State {
        #[serde(with = "StateNamespaceSerde")]
        namespace: StateNamespace,
        field: String,
    },
    /// Describes when a State field changes and its replacement.
    Model {
        description: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(remote = "StateNamespace", rename_all = "snake_case")]
enum StateNamespaceSerde {
    Default,
    Input,
    Tool,
}

impl ValueSpec {
    pub fn constant(value: impl Into<Value>) -> Self {
        Self::Constant { value: value.into() }
    }

    pub fn reference(namespace: StateNamespace, field: impl Into<String>) -> Self {
        Self::State {
            namespace,
            field: field.into(),
        }
    }

    pub fn model(description: impl Into<String>) -> Self {
        Self::Model {
            description: description.into(),
        }
    }

    pub(crate) fn is_model(&self) -> bool {
        matches!(self, Self::Model { .. })
    }

    pub(crate) fn read(&self, scope: &Scope) -> Result<Option<Value>, FlowError> {
        match self {
            Self::Constant { value } => Ok(Some(value.clone())),
            Self::Model { .. } => Ok(None),
            Self::State { namespace, field } => {
                let value = match namespace {
                    StateNamespace::Input => scope.get(*namespace, field),
                    _ => scope.state().get_in(*namespace, field),
                }
                .ok_or_else(|| format!("missing State reference {namespace}.{field}"))?;
                Ok(Some(value.clone()))
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Diagnostic> {
        match self {
            Self::State { field, .. } => nonblank(field, "State reference"),
            Self::Model { description } => nonblank(description, "model description"),
            Self::Constant { .. } => Ok(()),
        }
    }
}

/// Rejects empty or whitespace-only values, using `label` to identify the invalid setting in the error.
fn nonblank(value: &str, label: &str) -> Result<(), Diagnostic> {
    if value.trim().is_empty() {
        Err(Diagnostic::new(label, "must be nonblank"))
    } else {
        Ok(())
    }
}

impl StructuredSpec {
    /// Validates these rules and wraps an existing Step.
    /// Use [`lyquid_flow::FlowBuilder::flow_with`] to mount a wrapped child Flow with its graph,
    /// exit transitions, and Trace mode.
    pub fn with(self, inner: impl Step + 'static) -> Result<StructuredStep, BuildError> {
        self.validate()?;
        Ok(StructuredStep {
            inner: Arc::new(inner),
            spec: self,
        })
    }

    /// Validates the four section definitions.
    fn validate(&self) -> Result<(), Diagnostics> {
        let mut names = BTreeSet::new();
        for input in &self.inputs {
            nonblank(&input.name, "input name")?;
            if !names.insert(&input.name) {
                return Err(Diagnostic::new(format!("input {:?}", input.name), "duplicate input parameter").into());
            }
        }
        let mut templates: Vec<(String, &str)> = Vec::new();
        if let Some(output) = &self.output {
            output
                .value
                .validate()
                .map_err(|error| Diagnostics::from(error).at("output"))?;
            match &output.value {
                ValueSpec::Constant { value } => validate_type(&output.ty, value, "constant output")?,
                ValueSpec::Model { description } => templates.push(("output".into(), description)),
                ValueSpec::State { .. } => {}
            }
        }
        let mut fields = BTreeSet::new();
        for (field, value) in &self.state_updates {
            nonblank(field, "State update")?;
            if !fields.insert(field) {
                return Err(Diagnostic::new(format!("State update {field:?}"), "duplicate State update").into());
            }
            value.validate()?;
            if let ValueSpec::Model { description } = value {
                templates.push((field.clone(), description));
            }
        }
        let mut targets = BTreeSet::new();
        for case in &self.next {
            if let Some(next) = &case.next {
                nonblank(&next.0, "next Step")?;
            }
            if !targets.insert(case.next.as_ref()) {
                return Err(Diagnostic::new("next", "duplicate next Step").into());
            }
            nonblank(&case.description, "next Step description")?;
            templates.push(("next".into(), &case.description));
            if case.next.is_none() && !case.inputs.is_empty() {
                return Err(Diagnostic::new("next inputs", "root completion cannot receive arguments").into());
            }
            let mut arguments = BTreeSet::new();
            for (name, value) in &case.inputs {
                let context = format!(
                    "next {} input {name:?}",
                    case.next.as_ref().expect("arguments require a destination")
                );
                nonblank(name, "argument name").map_err(|error| Diagnostics::from(error).at(&context))?;
                if !arguments.insert(name) {
                    return Err(Diagnostic::new(context, "duplicate destination argument").into());
                }
                value
                    .validate()
                    .map_err(|error| Diagnostics::from(error).at(&context))?;
                if let ValueSpec::Model { description } = value {
                    templates.push((context, description));
                }
            }
        }
        for (label, text) in templates {
            Tera::default()
                .add_raw_template("check", text)
                .map_err(|error| Diagnostic::with_source(format!("invalid {label} template"), error))?;
        }
        Ok(())
    }

    /// Validates the specification and checks supplied arguments against Inputs.
    /// An absent input object is treated as empty; undeclared parameters are rejected.
    pub fn validate_inputs(&self, value: Option<&Value>) -> Result<(), Diagnostics> {
        self.validate()?;
        let empty = Map::new();
        let inputs = match value {
            None => &empty,
            Some(Value::Object(inputs)) => inputs,
            Some(_) => return Err(Diagnostic::new("invocation inputs", "must be an object").into()),
        };
        for input in &self.inputs {
            let context = format!("input {:?}", input.name);
            match inputs.get(&input.name) {
                Some(value) => validate_type(&input.ty, value, &context)?,
                None if input.required => return Err(Diagnostic::new(context, "missing required input").into()),
                None => {}
            }
        }
        for name in inputs.keys() {
            if !self.inputs.iter().any(|input| &input.name == name) {
                return Err(Diagnostic::new(format!("input {name:?}"), "undeclared input parameter").into());
            }
        }
        Ok(())
    }

    /// Validates the specification and checks a supplied value against Output.
    /// A value must be present exactly when Output is declared.
    pub fn validate_output(&self, value: Option<&Value>) -> Result<(), Diagnostics> {
        self.validate()?;
        match (&self.output, value) {
            (Some(output), Some(value)) => validate_type(&output.ty, value, "output"),
            (Some(_), None) => Err(Diagnostic::new("output", "missing declared output").into()),
            (None, Some(_)) => Err(Diagnostic::new("output", "Step declares no output").into()),
            (None, None) => Ok(()),
        }
    }
}

fn validate_type(ty: &Type, value: &Value, context: &str) -> Result<(), Diagnostics> {
    ty.validate(value)
        .map_err(|error| Diagnostic::with_source(context, error).into())
}
