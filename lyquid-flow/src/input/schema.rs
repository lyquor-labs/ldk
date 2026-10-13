//! This module generates JSON Schema from Rust field types and validates submissions against it.
//! Builders add Step-specific rules to that schema, so frontends and the runtime share the same
//! input requirements. The runtime checks the whole submission before decoding any field into
//! a Rust value.
//!
//! When `builder.field(..., prototype)` declares a field of type `T`, `generate::<T>()` uses Schemars
//! and `T`'s `JsonSchema` implementation to describe its JSON input structure. On submission,
//! `InputSpec::decode_values()` calls `validate()` with the completed schema and the
//! submitted JSON.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings, transform::transform_subschemas};
use serde_json::{Map, Number, Value as JsonValue, json};

// Keep non_blank's Unicode White_Space rule explicit; ECMAScript \s uses a different set.
pub(super) const NON_BLANK: &str =
    r"[^\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]";

// Match JSON Schema clients using ECMAScript Unicode mode, including character classes and escapes.
pub(super) fn compile_pattern(pattern: &str) -> Result<regress::Regex, String> {
    regress::Regex::with_flags(pattern, "u").map_err(|error| format!("invalid ECMAScript pattern: {error}"))
}

pub(super) fn generator() -> SchemaGenerator {
    SchemaSettings::draft2020_12()
        .for_deserialize()
        .with(|settings| settings.inline_subschemas = true)
        .into_generator()
}

pub(super) fn generate<T: JsonSchema>(generator: &mut SchemaGenerator) -> JsonValue {
    let mut schema = generator.subschema_for::<T>();
    normalize(&mut schema);
    schema.ensure_object();
    schema.into()
}

pub(super) fn with_definitions(schema: JsonValue, definitions: &Map<String, JsonValue>) -> JsonValue {
    let mut schema = Schema::try_from(schema).expect("generated schema is an object or boolean");
    if !definitions.is_empty() {
        schema
            .ensure_object()
            .insert("$defs".into(), definitions.clone().into());
    }
    normalize(&mut schema);
    schema.into()
}

// Schemars uses numeric formats for wider Rust integers. Export real bounds so both the
// frontend and the runtime enforce them before calling any retained field decoder.
fn normalize(schema: &mut Schema) {
    let bounds = match schema.get("format").and_then(JsonValue::as_str) {
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
    if let Some((minimum, maximum)) = bounds {
        for (keyword, bound, wider) in [
            ("minimum", minimum, Ordering::Less),
            ("maximum", maximum, Ordering::Greater),
        ] {
            let value = schema.ensure_object().entry(keyword).or_insert_with(|| bound.clone());
            if value
                .as_number()
                .is_some_and(|value| compare_numbers(value, bound.as_number().unwrap()) == wider)
            {
                *value = bound;
            }
        }
    }
    transform_subschemas(&mut normalize, schema);
}

fn resolve<'a>(root: &'a JsonValue, reference: &JsonValue) -> Result<&'a JsonValue, String> {
    let reference = reference.as_str().ok_or("schema reference must be a string")?;
    let pointer = reference
        .strip_prefix('#')
        .ok_or("only document-local schema references are supported")?;
    let pointer = percent_encoding::percent_decode_str(pointer)
        .decode_utf8()
        .map_err(|error| error.to_string())?;
    root.pointer(&pointer)
        .ok_or_else(|| format!("unresolved schema reference {reference}"))
}

/// Check supported JSON Schema constraints, local references, and reference cycles.
pub fn check(schema: &JsonValue) -> Result<(), String> {
    let mut references = BTreeSet::new();
    check_node(schema, schema, &mut references)?;
    let mut checked = BTreeSet::new();
    for reference in references {
        check_reference_cycles(
            resolve(schema, &reference.into())?,
            schema,
            &mut BTreeSet::new(),
            &mut checked,
        )?;
    }
    Ok(())
}

fn check_node(schema: &JsonValue, root: &JsonValue, references: &mut BTreeSet<String>) -> Result<(), String> {
    if schema.is_boolean() {
        return Ok(());
    }
    for (keyword, value) in schema.as_object().ok_or("schema must be an object or boolean")? {
        match keyword.as_str() {
            "$ref" => {
                let target = resolve(root, value)?;
                if references.insert(value.as_str().unwrap().to_owned()) {
                    check_node(target, root, references)?;
                }
            }
            "$defs" | "properties" => {
                for child in value
                    .as_object()
                    .ok_or_else(|| format!("{keyword} must be an object"))?
                    .values()
                {
                    check_node(child, root, references)?;
                }
            }
            "items" | "additionalProperties" | "not" | "if" | "then" | "else" => {
                check_node(value, root, references)?;
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                let children = value.as_array().ok_or_else(|| format!("{keyword} must be an array"))?;
                if children.is_empty() && keyword != "prefixItems" {
                    return Err(format!("{keyword} cannot be empty"));
                }
                for child in children {
                    check_node(child, root, references)?;
                }
            }
            "type" => {
                let valid = |value: &JsonValue| {
                    matches!(
                        value.as_str(),
                        Some("null" | "boolean" | "string" | "integer" | "number" | "array" | "object")
                    )
                };
                if !valid(value) &&
                    !value
                        .as_array()
                        .is_some_and(|kinds| !kinds.is_empty() && kinds.iter().all(valid))
                {
                    return Err("invalid schema type".into());
                }
            }
            "required" => {
                if !value
                    .as_array()
                    .is_some_and(|fields| fields.iter().all(JsonValue::is_string))
                {
                    return Err("required must list field names".into());
                }
            }
            "enum" => {
                if !value.as_array().is_some_and(|values| !values.is_empty()) {
                    return Err("enum must contain choices".into());
                }
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                if !value.is_number() {
                    return Err(format!("{keyword} must be a number"));
                }
            }
            "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties" | "maxProperties" => {
                if value.as_u64().is_none() {
                    return Err(format!("{keyword} must be a nonnegative integer"));
                }
            }
            "pattern" => {
                compile_pattern(value.as_str().ok_or("pattern must be a string")?)?;
            }
            "uniqueItems" => {
                if !value.is_boolean() {
                    return Err("uniqueItems must be boolean".into());
                }
            }
            "const" | "$schema" | "$comment" | "title" | "description" | "default" | "examples" | "format" |
            "deprecated" | "readOnly" | "writeOnly" => {}
            _ => return Err(format!("unsupported JSON Schema keyword {keyword}")),
        }
    }
    Ok(())
}

// Follow only edges that validate the same input value. Properties and array items descend into
// child values, so recursive data schemas remain valid. Every possible cycle contains a $ref;
// check() starts from each resolved target after checking the complete schema's structure.
fn check_reference_cycles(
    schema: &JsonValue, root: &JsonValue, active: &mut BTreeSet<*const JsonValue>,
    checked: &mut BTreeSet<*const JsonValue>,
) -> Result<(), String> {
    // Compare resolved node identities so different URI spellings cannot hide a cycle.
    let node = std::ptr::from_ref(schema);
    if checked.contains(&node) {
        return Ok(());
    }
    if !active.insert(node) {
        return Err("cyclic schema reference does not descend into a child input value".to_owned());
    }
    if let Some(reference) = schema.get("$ref") {
        check_reference_cycles(resolve(root, reference)?, root, active, checked)?;
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        for child in schema[keyword].as_array().into_iter().flatten() {
            check_reference_cycles(child, root, active, checked)?;
        }
    }
    for keyword in ["not", "if", "then", "else"] {
        if let Some(child) = schema.get(keyword) {
            check_reference_cycles(child, root, active, checked)?;
        }
    }
    active.remove(&node);
    checked.insert(node);
    Ok(())
}

fn integral(number: &Number) -> Option<i128> {
    if let Some(value) = number.as_i64() {
        return Some(i128::from(value));
    }
    if let Some(value) = number.as_u64() {
        return Some(i128::from(value));
    }
    let value = number.as_f64()?;
    (value.fract() == 0.0 && value >= i128::MIN as f64 && value < i128::MAX as f64).then_some(value as i128)
}

pub(super) fn compare_numbers(left: &Number, right: &Number) -> Ordering {
    match (integral(left), integral(right)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left.as_f64().unwrap().partial_cmp(&right.as_f64().unwrap()).unwrap(),
    }
}

pub(super) fn equal(left: &JsonValue, right: &JsonValue) -> bool {
    match (left, right) {
        (JsonValue::Number(left), JsonValue::Number(right)) => compare_numbers(left, right).is_eq(),
        (JsonValue::Array(left), JsonValue::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(left, right)| equal(left, right))
        }
        (JsonValue::Object(left), JsonValue::Object(right)) => {
            left.len() == right.len() &&
                left.iter()
                    .all(|(key, value)| right.get(key).is_some_and(|other| equal(value, other)))
        }
        _ => left == right,
    }
}

pub(super) fn validate(schema: &JsonValue, value: &JsonValue, path: &str) -> Result<(), super::InputError> {
    validate_at(schema, schema, value, path, None).map_err(ValidationError::into_input_error)
}

pub(crate) fn validate_bounded(schema: &JsonValue, value: &JsonValue, path: &str) -> Result<(), super::InputError> {
    validate_at(schema, schema, value, path, Some(0)).map_err(ValidationError::into_input_error)
}

// A depth limit aborts evaluation; it is not a schema mismatch that composition can negate or ignore.
enum ValidationError {
    Mismatch(super::InputError),
    DepthLimit(super::InputError),
}

impl ValidationError {
    fn into_input_error(self) -> super::InputError {
        match self {
            Self::Mismatch(error) | Self::DepthLimit(error) => error,
        }
    }
}

impl From<super::InputError> for ValidationError {
    fn from(error: super::InputError) -> Self {
        Self::Mismatch(error)
    }
}

fn matches_schema(result: Result<(), ValidationError>) -> Result<bool, ValidationError> {
    match result {
        Ok(()) => Ok(true),
        Err(ValidationError::Mismatch(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate_at(
    schema: &JsonValue, root: &JsonValue, value: &JsonValue, path: &str, depth: Option<usize>,
) -> Result<(), ValidationError> {
    let error = |message: &str| ValidationError::Mismatch(super::InputError::new(path, message));
    if depth.is_some_and(|depth| depth > 128) {
        return Err(ValidationError::DepthLimit(super::InputError::new(
            path,
            "schema validation exceeded 128 nested evaluations",
        )));
    }
    let child_depth = depth.map(|depth| depth + 1);
    if let Some(reference) = schema.get("$ref") {
        validate_at(
            resolve(root, reference).map_err(|message| error(&message))?,
            root,
            value,
            path,
            child_depth,
        )?;
    }
    if schema == &JsonValue::Bool(false) {
        return Err(error("value is not allowed"));
    }
    let matches_type = |kind: &str| match kind {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "string" => value.is_string(),
        "integer" => value.as_number().is_some_and(|number| {
            integral(number).is_some() || number.as_f64().is_some_and(|number| number.fract() == 0.0)
        }),
        "number" => value.is_number(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => false,
    };
    if let Some(kind) = schema.get("type") {
        let matches = match kind {
            JsonValue::String(kind) => matches_type(kind),
            JsonValue::Array(kinds) => kinds.iter().filter_map(JsonValue::as_str).any(matches_type),
            _ => false,
        };
        if !matches {
            return Err(error(&format!("expected {kind}")));
        }
    }
    if schema.get("const").is_some_and(|expected| !equal(expected, value)) {
        return Err(error("value differs from the declared constant"));
    }
    if schema["enum"]
        .as_array()
        .is_some_and(|choices| !choices.iter().any(|choice| equal(choice, value)))
    {
        return Err(error("value is not one of the declared choices"));
    }
    if let Some(number) = value.as_number() {
        for (keyword, ordering, inclusive) in [
            ("minimum", Ordering::Less, true),
            ("maximum", Ordering::Greater, true),
            ("exclusiveMinimum", Ordering::Less, false),
            ("exclusiveMaximum", Ordering::Greater, false),
        ] {
            if schema[keyword].as_number().is_some_and(|bound| {
                let comparison = compare_numbers(number, bound);
                comparison == ordering || (!inclusive && comparison == Ordering::Equal)
            }) {
                return Err(error(&format!("value violates {keyword}")));
            }
        }
    }
    if let Some(text) = value.as_str() {
        length(schema, text.chars().count(), "minLength", "maxLength", path)?;
        if let Some(pattern) = schema["pattern"].as_str() {
            let regex = compile_pattern(pattern).map_err(|cause| error(&cause))?;
            if regex.find(text).is_none() {
                return Err(error("text does not match the declared pattern"));
            }
        }
    }
    if let Some(items) = value.as_array() {
        length(schema, items.len(), "minItems", "maxItems", path)?;
        for (index, item) in items.iter().enumerate() {
            if let Some(item_schema) = schema["prefixItems"].get(index).or_else(|| schema.get("items")) {
                validate_at(item_schema, root, item, &format!("{path}/{index}"), child_depth)?;
            }
            if schema["uniqueItems"] == true && items[..index].iter().any(|previous| equal(previous, item)) {
                return Err(error("list items must be unique"));
            }
        }
    }
    if let Some(values) = value.as_object() {
        length(schema, values.len(), "minProperties", "maxProperties", path)?;
        if let Some(required) = schema["required"].as_array() {
            for key in required.iter().filter_map(JsonValue::as_str) {
                if !values.contains_key(key) {
                    return Err(super::InputError::new(
                        format!("{path}/{}", super::escape_pointer(key)),
                        format!("missing required field {key}"),
                    )
                    .into());
                }
            }
        }
        for (key, value) in values {
            let property = schema["properties"]
                .get(key)
                .or_else(|| schema.get("additionalProperties"));
            if let Some(property) = property {
                validate_at(
                    property,
                    root,
                    value,
                    &format!("{path}/{}", super::escape_pointer(key)),
                    child_depth,
                )?;
            }
        }
    }
    if let Some(schemas) = schema["allOf"].as_array() {
        for schema in schemas {
            validate_at(schema, root, value, path, child_depth)?;
        }
    }
    if let Some(schemas) = schema["anyOf"].as_array() {
        let mut matched = false;
        for schema in schemas {
            if matches_schema(validate_at(schema, root, value, path, child_depth))? {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(error("value does not match any permitted type"));
        }
    }
    if let Some(schemas) = schema["oneOf"].as_array() {
        let mut matches = 0;
        for schema in schemas {
            matches += usize::from(matches_schema(validate_at(schema, root, value, path, child_depth))?);
        }
        if matches != 1 {
            return Err(error("value must match exactly one permitted type"));
        }
    }
    if let Some(schema) = schema.get("not") &&
        matches_schema(validate_at(schema, root, value, path, child_depth))?
    {
        return Err(error("value matches a forbidden schema"));
    }
    if let Some(condition) = schema.get("if") {
        if matches_schema(validate_at(condition, root, value, path, child_depth))? {
            if let Some(consequence) = schema.get("then") {
                validate_at(consequence, root, value, path, child_depth)?;
            }
        } else if let Some(alternative) = schema.get("else") {
            validate_at(alternative, root, value, path, child_depth)?;
        }
    }
    Ok(())
}

fn length(schema: &JsonValue, count: usize, min: &str, max: &str, path: &str) -> Result<(), super::InputError> {
    if schema[min].as_u64().is_some_and(|min| (count as u64) < min) ||
        schema[max].as_u64().is_some_and(|max| (count as u64) > max)
    {
        return Err(super::InputError::new(path, "length is outside the declared bounds"));
    }
    Ok(())
}
