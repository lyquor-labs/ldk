//! Inspectable Step arguments and results. These declarations contain no runtime values or callbacks.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use lyquid_flow::{InputSpec, check_json_schema, validate_json_schema};
use schemars::{JsonSchema, Schema, generate::SchemaSettings, transform::transform_subschemas};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{BindingTarget, NextStep, StepWiring, ValueSource};

pub(crate) type ModelCodec =
    Arc<dyn Fn(&lyquid_flow::Scope, Option<&lyquid_flow::StateUpdates>, &str) -> Result<Value, String> + Send + Sync>;

/// Missing is distinct from JSON null. Only an explicit default supplies an absent argument.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Presence {
    Required,
    Optional,
    Default { value: Value },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataArgument {
    pub schema: Value,
    pub presence: Presence,
}

/// A model proposal uses the State destination of a final-result binding at `pointer`.
/// Actions address the proposal by its logical name, independently of that State field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelOutput {
    pub schema: Value,
    pub pointer: String,
    pub criterion: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepData {
    pub arguments: BTreeMap<String, DataArgument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub model_outputs: BTreeMap<String, ModelOutput>,
}

impl StepData {
    pub(crate) fn validate(&self, wiring: &StepWiring, require_bound: bool) -> Result<(), String> {
        if let Some(schema) = &self.result {
            check_json_schema(schema).map_err(|e| format!("result schema: {e}"))?;
            if let NextStep::Result { pointer, .. } = &wiring.next {
                let projected =
                    project_schema(schema, schema, pointer).map_err(|error| format!("result route: {error}"))?;
                if let Some(projected) = projected &&
                    !schema_types(schema, projected).contains("string")
                {
                    return Err(format!("result route at {pointer:?} cannot be a string"));
                }
            }
        }
        for (name, argument) in &self.arguments {
            valid_name(name)?;
            check_json_schema(&argument.schema).map_err(|e| format!("argument {name}: {e}"))?;
            if let Presence::Default { value } = &argument.presence {
                validate_json_schema(&argument.schema, value, &format!("argument {name} default"))?;
            }
            let binding = wiring
                .bindings
                .iter()
                .find(|binding| matches!(&binding.to, BindingTarget::Context { name: target } if target == name));
            if require_bound && binding.is_none() && matches!(argument.presence, Presence::Required) {
                return Err(format!("required data argument {name:?} has no binding"));
            }
            if let Some(binding) = binding &&
                let Some(value) = constant_value(&binding.from)?
            {
                validate_json_schema(&argument.schema, &value, &format!("argument {name}"))?;
            }
        }
        for binding in &wiring.bindings {
            if let BindingTarget::Context { name } = &binding.to &&
                !self.arguments.is_empty() &&
                !self.arguments.contains_key(name)
            {
                return Err(format!("undeclared data argument {name:?}"));
            }
            if let Some(schema) = &self.result &&
                let Some(pointer) = result_pointer(&binding.from)
            {
                check_projection(schema, &pointer)?;
            }
        }
        for (name, output) in &self.model_outputs {
            valid_name(name)?;
            check_json_schema(&output.schema).map_err(|e| format!("model output {name}: {e}"))?;
            crate::builder::validate_pointer(&output.pointer)?;
            if let Some(schema) = &self.result {
                check_projection(schema, &output.pointer)?;
            }
            if require_bound {
                self.model_field(wiring, name)?;
            }
        }
        Ok(())
    }

    pub(crate) fn model_field<'a>(&self, wiring: &'a StepWiring, name: &str) -> Result<&'a str, String> {
        let output = &self.model_outputs[name];
        let mut fields = wiring.bindings.iter().filter_map(|binding| match &binding.to {
            BindingTarget::State { field }
                if result_pointer(&binding.from).is_some_and(|pointer| pointer == output.pointer) =>
            {
                Some(field.as_str())
            }
            _ => None,
        });
        match (fields.next(), fields.next()) {
            (Some(field), None) => Ok(field),
            _ => Err(format!(
                "model output {name:?} requires exactly one result-to-State binding at {:?}",
                output.pointer
            )),
        }
    }

    /// Only a retained static specification supplies source declarations during construction.
    /// Factories and State codecs need a Scope and remain runtime checks.
    pub(crate) fn validate_input_bindings(&self, wiring: &StepWiring, input: &InputSpec) -> Result<(), String> {
        for binding in &wiring.bindings {
            let (name, fallback) = match binding.from.root() {
                ValueSource::Input { name } => (name, None),
                ValueSource::InputOr { name, default } => (name, Some(default)),
                _ => continue,
            };
            let endpoint = format!("input {name:?} binding to {:?}", binding.to);
            let source = input
                .field_schema(name)
                .ok_or_else(|| format!("{endpoint}: unknown input field"))?;
            let mut pointers = Vec::new();
            selection_pointers(&binding.from, &mut pointers);
            let projected = pointers
                .iter()
                .try_fold(Some(source), |schema, pointer| {
                    schema
                        .map(|schema| project_schema(input.schema(), schema, pointer))
                        .transpose()
                        .map(Option::flatten)
                })
                .map_err(|error| format!("{endpoint}: {error}"))?;
            let argument = match &binding.to {
                BindingTarget::Context { name } => self.arguments.get(name),
                BindingTarget::State { .. } => None,
            };
            if let (Some(source), Some(argument)) = (projected, argument) {
                let source_types = schema_types(input.schema(), source);
                let argument_types = schema_types(&argument.schema, &argument.schema);
                if source_types.is_disjoint(&argument_types) {
                    return Err(format!(
                        "{endpoint}: incompatible declared types {source_types:?} and {argument_types:?}"
                    ));
                }
            }
            // A required input never takes its fallback. Optional input defaults are authored
            // values, so check them with the same validator used for argument defaults.
            if let Some(fallback) = fallback &&
                !input.schema()["required"]
                    .as_array()
                    .is_some_and(|required| required.iter().any(|field| field.as_str() == Some(name)))
            {
                let value = pointers.iter().try_fold(fallback, |value, pointer| {
                    value
                        .pointer(pointer)
                        .ok_or_else(|| format!("{endpoint}: fallback is missing {pointer:?}"))
                })?;
                if let Some(argument) = argument {
                    validate_json_schema(&argument.schema, value, &format!("{endpoint} fallback"))?;
                }
            }
        }
        Ok(())
    }
}

fn result_pointer(source: &ValueSource) -> Option<String> {
    let ValueSource::Result { pointer } = source.root() else {
        return None
    };
    let mut pointers = vec![pointer.as_str()];
    selection_pointers(source, &mut pointers);
    Some(pointers.concat())
}

fn selection_pointers<'a>(source: &'a ValueSource, pointers: &mut Vec<&'a str>) {
    if let ValueSource::Select { source, pointer } = source {
        selection_pointers(source, pointers);
        pointers.push(pointer);
    }
}

// An upper bound on the JSON types accepted by a schema. Overlapping types, constraints,
// and custom codecs still require runtime validation; this is not schema implication.
fn schema_types(root: &Value, schema: &Value) -> BTreeSet<&'static str> {
    fn named(name: &str) -> BTreeSet<&'static str> {
        match name {
            "null" => BTreeSet::from(["null"]),
            "boolean" => BTreeSet::from(["boolean"]),
            "string" => BTreeSet::from(["string"]),
            "integer" => BTreeSet::from(["integer"]),
            "number" => BTreeSet::from(["integer", "fractional number"]),
            "array" => BTreeSet::from(["array"]),
            "object" => BTreeSet::from(["object"]),
            _ => unreachable!("schema types have already been checked"),
        }
    }

    let mut types = BTreeSet::from([
        "null",
        "boolean",
        "string",
        "integer",
        "fractional number",
        "array",
        "object",
    ]);
    if schema == &Value::Bool(false) {
        return BTreeSet::new();
    }
    if let Some(kind) = schema.get("type") {
        types = match kind.as_str() {
            Some(name) => named(name),
            None => kind
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|name| named(name.as_str().unwrap()))
                .collect(),
        };
    }
    if let Some(reference) = schema["$ref"].as_str() &&
        let Some(target) = reference.strip_prefix('#').and_then(|pointer| root.pointer(pointer))
    {
        types = types.intersection(&schema_types(root, target)).copied().collect();
    }
    for child in schema["allOf"].as_array().into_iter().flatten() {
        types = types.intersection(&schema_types(root, child)).copied().collect();
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(children) = schema[keyword].as_array() {
            let alternatives = children.iter().flat_map(|child| schema_types(root, child)).collect();
            types = types.intersection(&alternatives).copied().collect();
        }
    }
    types
}

pub(crate) fn valid_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        Err("data name must be nonblank".into())
    } else {
        Ok(())
    }
}

pub(crate) fn schema<T: JsonSchema>(output: bool) -> Value {
    let settings = SchemaSettings::draft2020_12();
    let settings = if output {
        settings.for_serialize()
    } else {
        settings.for_deserialize()
    };
    let mut schema = settings.into_generator().into_root_schema_for::<T>();
    normalize_numbers(&mut schema);
    schema.into()
}

// JSON Schema's format is an annotation; retain the integer bounds enforced by native codecs.
fn normalize_numbers(schema: &mut Schema) {
    let bounds = match schema.get("format").and_then(Value::as_str) {
        Some("int8") => Some((json!(i8::MIN), json!(i8::MAX))),
        Some("int16") => Some((json!(i16::MIN), json!(i16::MAX))),
        Some("int32") => Some((json!(i32::MIN), json!(i32::MAX))),
        Some("int64") => Some((json!(i64::MIN), json!(i64::MAX))),
        Some("int") => Some((json!(isize::MIN), json!(isize::MAX))),
        Some("uint8") => Some((json!(0), json!(u8::MAX))),
        Some("uint16") => Some((json!(0), json!(u16::MAX))),
        Some("uint32") => Some((json!(0), json!(u32::MAX))),
        Some("uint64") => Some((json!(0), json!(u64::MAX))),
        Some("uint") => Some((json!(0), json!(usize::MAX))),
        _ => None,
    };
    if let Some((min, max)) = bounds {
        // Preserve authored bounds as well as the native type's range.
        schema
            .ensure_object()
            .entry("allOf")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("generated allOf is an array")
            .push(json!({"minimum": min, "maximum": max}));
        // Stop the traversal from revisiting this annotation on another normalization pass.
        schema.ensure_object().remove("format");
    }
    transform_subschemas(&mut normalize_numbers, schema);
}

fn constant_value(source: &ValueSource) -> Result<Option<Value>, String> {
    match source {
        ValueSource::Constant { value } => Ok(Some(value.clone())),
        ValueSource::Select { source, pointer } => constant_value(source)?
            .map(|value| {
                value
                    .pointer(pointer)
                    .cloned()
                    .ok_or_else(|| format!("constant is missing {pointer:?}"))
            })
            .transpose(),
        _ => Ok(None),
    }
}

// Check paths only where the schema makes their absence certain. General schema implication,
// conditional shapes, and runtime array lengths remain value-dependent checks.
fn check_projection(root: &Value, pointer: &str) -> Result<(), String> {
    project_schema(root, root, pointer)
        .map(|_| ())
        .map_err(|error| format!("result {error}"))
}

fn resolve_references<'a>(root: &'a Value, mut schema: &'a Value) -> Option<&'a Value> {
    while let Some(reference) = schema["$ref"].as_str() {
        schema = root.pointer(reference.strip_prefix('#')?)?;
    }
    Some(schema)
}

fn project_schema<'a>(root: &'a Value, mut schema: &'a Value, pointer: &str) -> Result<Option<&'a Value>, String> {
    crate::builder::validate_pointer(pointer)?;
    for segment in pointer.split('/').skip(1) {
        let Some(resolved) = resolve_references(root, schema) else {
            return Ok(None)
        };
        schema = resolved;
        let segment = segment.replace("~1", "/").replace("~0", "~");
        schema = match schema["type"].as_str() {
            Some("object") => match schema["properties"].get(&segment) {
                Some(property) => property,
                None if schema["additionalProperties"] == false => {
                    return Err(format!("schema has no field at {pointer:?}"));
                }
                None => match schema.get("additionalProperties") {
                    Some(additional) => additional,
                    None => return Ok(None),
                },
            },
            Some("array") => {
                let index = segment
                    .parse::<usize>()
                    .ok()
                    .filter(|_| {
                        segment.bytes().all(|byte| byte.is_ascii_digit()) &&
                            (segment == "0" || !segment.starts_with('0'))
                    })
                    .ok_or_else(|| format!("array path requires an index: {pointer:?}"))?;
                if schema["maxItems"]
                    .as_u64()
                    .is_some_and(|maximum| index as u64 >= maximum)
                {
                    return Err(format!("array schema has no index at {pointer:?}"));
                }
                let item = schema["prefixItems"]
                    .as_array()
                    .and_then(|items| items.get(index))
                    .or_else(|| schema.get("items"));
                let Some(item) = item else { return Ok(None) };
                item
            }
            Some("string" | "integer" | "number" | "boolean" | "null") => {
                return Err(format!("path traverses a scalar at {pointer:?}"));
            }
            _ => return Ok(None),
        };
    }
    if resolve_references(root, schema) == Some(&Value::Bool(false)) {
        return Err(format!("schema forbids the value at {pointer:?}"));
    }
    // Preserve constraints alongside a terminal $ref for the argument type check.
    Ok(Some(schema))
}
