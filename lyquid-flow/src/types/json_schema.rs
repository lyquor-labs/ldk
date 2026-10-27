//! JSON Schema generation, checking, and validation for Input contracts and consumers.
//!
//! Native Rust declarations use Schemars. Input builders add their field constraints and use
//! this schema validator. Core `Type` validation checks JSON values directly.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use schemars::{
    JsonSchema, Schema as JsonSchemaDocument, SchemaGenerator, generate::SchemaSettings,
    transform::transform_subschemas,
};
use serde_json::{Map, Number, Value as JsonValue, json};

use crate::Diagnostic;
use crate::error::Error;

// Keep non_blank's Unicode White_Space rule explicit; ECMAScript \s uses a different set.
pub(crate) const NON_BLANK: &str =
    r"[^\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]";

// Match JSON Schema clients using ECMAScript Unicode mode, including character classes and escapes.
pub(crate) fn compile_pattern(pattern: &str) -> Result<regress::Regex, Diagnostic> {
    regress::Regex::with_flags(pattern, "u")
        .map_err(|error| Diagnostic::with_source(format!("invalid ECMAScript pattern {pattern:?}"), error))
}

pub(crate) fn generator() -> SchemaGenerator {
    SchemaSettings::draft2020_12()
        .for_deserialize()
        .with(|settings| settings.inline_subschemas = true)
        .into_generator()
}

pub(crate) fn generate<T: JsonSchema>(generator: &mut SchemaGenerator) -> JsonValue {
    let mut schema = generator.subschema_for::<T>();
    normalize(&mut schema);
    schema.ensure_object();
    schema.into()
}

pub(crate) fn with_definitions(schema: JsonValue, definitions: &Map<String, JsonValue>) -> JsonValue {
    let mut schema = JsonSchemaDocument::try_from(schema).expect("generated schema is an object or boolean");
    if !definitions.is_empty() {
        schema
            .ensure_object()
            .insert("$defs".into(), definitions.clone().into());
    }
    normalize(&mut schema);
    schema.into()
}

// Turn Schemars' numeric format annotations into bounds enforced by schema consumers.
fn normalize(schema: &mut JsonSchemaDocument) {
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

fn resolve<'a>(root: &'a JsonValue, reference: &JsonValue) -> Result<&'a JsonValue, Diagnostic> {
    let reference = reference
        .as_str()
        .ok_or_else(|| Diagnostic::new("schema", "schema reference must be a string"))?;
    let pointer = reference
        .strip_prefix('#')
        .ok_or_else(|| Diagnostic::new(reference, "only document-local schema references are supported"))?;
    let pointer = percent_encoding::percent_decode_str(pointer)
        .decode_utf8()
        .map_err(|source| Diagnostic::with_source(reference, source))?;
    root.pointer(&pointer)
        .ok_or_else(|| Diagnostic::new(reference, "unresolved schema reference"))
}

/// Check supported JSON Schema constraints, local references, and reference cycles.
pub fn check(schema: &JsonValue) -> Result<(), Diagnostic> {
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

fn check_node(schema: &JsonValue, root: &JsonValue, references: &mut BTreeSet<String>) -> Result<(), Diagnostic> {
    if schema.is_boolean() {
        return Ok(());
    }
    for (keyword, value) in schema
        .as_object()
        .ok_or_else(|| Diagnostic::new("schema", "schema must be an object or boolean"))?
    {
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
                    .ok_or_else(|| Diagnostic::new(keyword, "must be an object"))?
                    .values()
                {
                    check_node(child, root, references)?;
                }
            }
            "items" | "additionalProperties" | "not" | "if" | "then" | "else" => {
                check_node(value, root, references)?;
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                let children = value
                    .as_array()
                    .ok_or_else(|| Diagnostic::new(keyword, "must be an array"))?;
                if children.is_empty() && keyword != "prefixItems" {
                    return Err(Diagnostic::new(keyword, "cannot be empty"));
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
                    return Err(Diagnostic::new("schema", "invalid schema type"));
                }
            }
            "required" => {
                if !value
                    .as_array()
                    .is_some_and(|fields| fields.iter().all(JsonValue::is_string))
                {
                    return Err(Diagnostic::new("required", "must list field names"));
                }
            }
            "enum" => {
                if !value.as_array().is_some_and(|values| !values.is_empty()) {
                    return Err(Diagnostic::new("enum", "must contain choices"));
                }
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                if !value.is_number() {
                    return Err(Diagnostic::new(keyword, "must be a number"));
                }
            }
            "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties" | "maxProperties" => {
                if value.as_u64().is_none() {
                    return Err(Diagnostic::new(keyword, "must be a nonnegative integer"));
                }
            }
            "pattern" => {
                compile_pattern(
                    value
                        .as_str()
                        .ok_or_else(|| Diagnostic::new(keyword, "must be a string"))?,
                )?;
            }
            "uniqueItems" => {
                if !value.is_boolean() {
                    return Err(Diagnostic::new(keyword, "must be boolean"));
                }
            }
            "const" | "$schema" | "$comment" | "title" | "description" | "default" | "examples" | "format" |
            "deprecated" | "readOnly" | "writeOnly" => {}
            _ => {
                return Err(Diagnostic::new(
                    keyword.clone(),
                    format!("unsupported JSON Schema keyword {keyword}"),
                ))
            }
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
) -> Result<(), Diagnostic> {
    // Compare resolved node identities so different URI spellings cannot hide a cycle.
    let node = std::ptr::from_ref(schema);
    if checked.contains(&node) {
        return Ok(());
    }
    if !active.insert(node) {
        return Err(Diagnostic::new(
            "schema",
            "cyclic schema reference does not descend into a child input value",
        ));
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

fn is_integer(number: &Number) -> bool {
    number.is_i64() || number.is_u64() || number.as_f64().is_some_and(|value| value.fract() == 0.0)
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

pub(crate) fn compare_numbers(left: &Number, right: &Number) -> Ordering {
    match (integral(left), integral(right)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left.as_f64().unwrap().partial_cmp(&right.as_f64().unwrap()).unwrap(),
    }
}

pub(crate) fn equal(left: &JsonValue, right: &JsonValue) -> bool {
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

pub(crate) fn validate(schema: &JsonValue, value: &JsonValue, path: &str) -> Result<(), Error> {
    validate_at(schema, schema, value, path, None).map_err(ValidationError::into_error)
}

/// Validate a JSON value against a checked schema. Recursive validation is limited to 128 nested evaluations.
/// Exceeding the limit aborts validation, including within schema composition.
/// This limit applies to this entry point only; `InputSpec` validation is unchanged.
pub fn validate_json_schema(schema: &JsonValue, value: &JsonValue, path: &str) -> Result<(), Error> {
    validate_at(schema, schema, value, path, Some(0)).map_err(ValidationError::into_error)
}

// A depth limit aborts evaluation; it is not a schema mismatch that composition can negate or ignore.
enum ValidationError {
    Mismatch(Error),
    DepthLimit(Error),
}

impl ValidationError {
    fn into_error(self) -> Error {
        match self {
            Self::Mismatch(error) | Self::DepthLimit(error) => error,
        }
    }
}

impl From<Error> for ValidationError {
    fn from(error: Error) -> Self {
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
    let error = |message: &str| ValidationError::Mismatch(Error::new(path, message));
    if depth.is_some_and(|depth| depth > 128) {
        return Err(ValidationError::DepthLimit(Error::new(
            path,
            "schema validation exceeded 128 nested evaluations",
        )));
    }
    let child_depth = depth.map(|depth| depth + 1);
    if let Some(reference) = schema.get("$ref") {
        validate_at(
            resolve(root, reference).map_err(|message| error(&message.to_string()))?,
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
        "integer" => value.as_number().is_some_and(is_integer),
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
            let regex = compile_pattern(pattern).map_err(|cause| error(&cause.to_string()))?;
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
                    return Err(Error::new(
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

fn length(schema: &JsonValue, count: usize, min: &str, max: &str, path: &str) -> Result<(), Error> {
    if schema[min].as_u64().is_some_and(|min| (count as u64) < min) ||
        schema[max].as_u64().is_some_and(|max| (count as u64) > max)
    {
        return Err(Error::new(path, "length is outside the declared bounds"));
    }
    Ok(())
}
