//! Typed, atomic field input contracts.
//!
//! A Step declares an input page with `InputSpec::builder()`. Each field declaration creates its
//! JSON Schema property, retains its `Value` decoder, and emits a native UI component through the
//! shared `ui` builder.
//!
//! ```rust
//! use lyquid_flow::{InputSpec, List};
//!
//! let mut builder = InputSpec::builder();
//! let recipient = builder
//!     .field("recipient", "Recipient", String::new())
//!     .non_blank()
//!     .text_input();
//! let preferences = builder
//!     .field("preferences", "Preferences", List::<String>(vec![]))
//!     .item_choices([("quiet", "Quiet"), ("portable", "Portable")])
//!     .unique()
//!     .min_len(1)
//!     .max_len(2)
//!     .select_many();
//! let submit = builder.submit("Continue");
//! let layout = builder.ui().column(vec![recipient, preferences, submit]);
//! let spec = builder.finish(layout)?;
//! # Ok::<(), String>(())
//! ```
//!
//! An input submission is a JSON object mapping field names to values.
//! Each value must already have the JSON type required by its field's schema.
//! The runtime validates these types without coercion.
//!
//! For example: `{"recipient":"Alex","preferences":["portable"]}`.
//! The framework checks the whole generated schema before invoking any field decoder. It then decodes
//! every provided field and checks the returned concrete Rust type. Only after all fields succeed does
//! the runner bind `input.recipient` and `input.preferences`. No partial binding occurs. Temporary input
//! disappears after the turn, including a failed turn.

use std::fmt;

use lyquid::prelude::{HashMap, new_hashmap};
use schemars::{JsonSchema, SchemaGenerator};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value as JsonValue, json};

use crate::Value;
use crate::ui::{self, Choice, Node, UiDocument};

pub(crate) mod schema;

/// A submitted JSON object mapping field names to values.
/// Each value must already have the JSON type required by its field's schema.
/// The runtime validates these types without coercion.
pub type Input = JsonValue;

/// A retained input page and its complete validation and decoding contract.
///
/// JSON deserialization validates the UI and schema, then retains `serde_json::Value` decoders for
/// the declared fields. These fields are read as JSON values; structured-step bindings can decode
/// them into typed arguments or State replacements. Rust-built specs retain their original codecs.
#[derive(Clone, Serialize)]
pub struct InputSpec {
    ui: UiDocument,
    schema: JsonValue,
    #[serde(skip)]
    fields: HashMap<String, Box<dyn Value>>,
}

impl<'de> Deserialize<'de> for InputSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Specification {
            ui: UiDocument,
            schema: JsonValue,
        }

        let Specification { ui, schema } = Specification::deserialize(deserializer)?;
        schema::check(&schema).map_err(serde::de::Error::custom)?;
        if schema["type"] != "object" || schema["additionalProperties"] != false {
            return Err(serde::de::Error::custom(
                "input schema requires type object and additionalProperties false",
            ));
        }
        let properties = schema["properties"]
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("input schema requires properties"))?;
        let mut fields = new_hashmap();
        for name in properties.keys() {
            if name.is_empty() {
                return Err(serde::de::Error::custom("input field name must not be empty"));
            }
            fields.insert(name.clone(), Box::new(JsonValue::Null) as Box<dyn Value>);
        }
        Ok(Self { ui, schema, fields })
    }
}

/// A validation or decoding failure at a JSON Pointer in the submitted field object.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{path}: {message}")]
pub struct InputError {
    pub path: String,
    pub message: String,
}

impl InputError {
    pub(crate) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Decoded fields delivered to the runner only after the complete submission succeeds.
pub(crate) type DecodedInput = HashMap<String, Box<dyn Value>>;

impl InputSpec {
    pub fn builder() -> InputSpecBuilder {
        InputSpecBuilder::default()
    }

    pub fn ui(&self) -> &UiDocument {
        &self.ui
    }

    pub fn schema(&self) -> &JsonValue {
        &self.schema
    }

    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.schema["properties"]
            .as_object()
            .into_iter()
            .flat_map(|fields| fields.keys().map(String::as_str))
    }

    pub fn field_schema(&self, key: &str) -> Option<&JsonValue> {
        self.schema["properties"].get(key)
    }

    /// Parses a submitted object, rejecting duplicate top-level field names before validation.
    pub fn decode(&self, encoded: &str) -> Result<HashMap<String, Box<dyn Value>>, InputError> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Map<String, JsonValue>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a complete field-value object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut entries: M) -> Result<Self::Value, M::Error> {
                let mut values = Map::new();
                while let Some((key, value)) = entries.next_entry::<String, JsonValue>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!("duplicate input field {key}")));
                    }
                }
                Ok(values)
            }
        }

        let mut deserializer = serde_json::Deserializer::from_str(encoded);
        let values = deserializer
            .deserialize_map(ObjectVisitor)
            .map_err(|error| InputError::new("", error.to_string()))?;
        deserializer
            .end()
            .map_err(|error| InputError::new("", error.to_string()))?;
        self.decode_values(&JsonValue::Object(values))
    }

    /// Validates the entire object before invoking any retained decoder. The local map is returned only
    /// after every decoder succeeds with its declared concrete Rust type. Omission is not a default.
    pub fn decode_values(&self, values: &JsonValue) -> Result<HashMap<String, Box<dyn Value>>, InputError> {
        schema::validate(&self.schema, values, "")?;
        let mut fields = new_hashmap();
        for (key, encoded) in values
            .as_object()
            .ok_or_else(|| InputError::new("", "input must be an object"))?
        {
            let prototype = self
                .fields
                .get(key)
                .ok_or_else(|| InputError::new(format!("/{}", escape_pointer(key)), "unknown input field"))?;
            let decoded = prototype
                .decode(&encoded.to_string())
                .map_err(|error| InputError::new(format!("/{}", escape_pointer(key)), error))?;
            if prototype.as_ref().type_id() != decoded.as_ref().type_id() {
                return Err(InputError::new(
                    format!("/{}", escape_pointer(key)),
                    "decoder returned a different concrete value type",
                ));
            }
            fields.insert(key.clone(), decoded);
        }
        Ok(fields)
    }
}

pub struct InputSpecBuilder {
    generator: SchemaGenerator,
    ui: ui::Builder,
    fields: HashMap<String, Box<dyn Value>>,
    properties: Map<String, JsonValue>,
    required: Vec<String>,
    conditions: Vec<(String, Vec<JsonValue>, JsonValue)>,
    errors: Vec<String>,
}

impl Default for InputSpecBuilder {
    fn default() -> Self {
        Self {
            generator: schema::generator(),
            ui: ui::Builder::default(),
            fields: new_hashmap(),
            properties: Map::new(),
            required: Vec::new(),
            conditions: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl InputSpecBuilder {
    pub fn ui(&self) -> &ui::Builder {
        &self.ui
    }

    /// Declares schema, retained decoder, and input UI from one business field declaration.
    /// The prototype is never exported as draft data or used to infer the field's type.
    pub fn field<V: Value + JsonSchema>(
        &mut self, key: impl Into<String>, label: impl Into<String>, prototype: V,
    ) -> FieldBuilder<'_> {
        let key = key.into();
        let label = label.into();
        if key.is_empty() || self.fields.contains_key(&key) {
            self.errors.push(format!("empty or duplicate input field {key:?}"));
        }
        let mut schema = schema::generate::<V>(&mut self.generator);
        let base_schema = schema::with_definitions(schema.clone(), self.generator.definitions());
        schema["title"] = label.clone().into();
        self.properties.insert(key.clone(), schema);
        self.fields.insert(key.clone(), Box::new(prototype));
        self.required.push(key.clone());
        FieldBuilder {
            owner: self,
            key,
            label,
            base_schema,
            choices: Vec::new(),
            item_choices: Vec::new(),
        }
    }

    /// Adds a submit control for the complete field object.
    pub fn submit(&self, label: impl AsRef<str>) -> Node {
        self.ui.submit(label.as_ref(), Map::new())
    }

    /// Submits the form with these explicit field values, for example an action selected by a button.
    /// Declare the fields first. Button values override drafts and are validated with the complete input.
    pub fn submit_with<K: Into<String>, V: Into<JsonValue>>(
        &mut self, label: impl AsRef<str>, values: impl IntoIterator<Item = (K, V)>,
    ) -> Node {
        let values = values
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect::<Map<_, _>>();
        for (key, value) in &values {
            if !self.properties.get(key).is_some_and(|property| {
                schema::validate(
                    &schema::with_definitions(property.clone(), self.generator.definitions()),
                    value,
                    key,
                )
                .is_ok()
            }) {
                self.errors
                    .push(format!("submit button has an invalid value for {key}"));
            }
        }
        self.ui.submit(label.as_ref(), values)
    }

    pub fn finish(mut self, root: Node) -> Result<InputSpec, String> {
        let mut conditional = Vec::new();
        for (field, values, consequence) in &self.conditions {
            let Some(property) = self.properties.get(field) else {
                self.errors.push(format!("condition refers to unknown field {field}"));
                continue;
            };
            if values.is_empty() {
                self.errors
                    .push("a field condition must have at least one value".to_owned());
            }
            for value in values {
                if schema::validate(
                    &schema::with_definitions(property.clone(), self.generator.definitions()),
                    value,
                    field,
                )
                .is_err()
                {
                    self.errors.push(format!("condition has an invalid value for {field}"));
                }
            }
            conditional.push(json!({
                "if": {"required": [field], "properties": {field: {"enum": values}}},
                "then": consequence,
            }));
        }
        if !self.errors.is_empty() {
            return Err(self.errors.join("; "));
        }
        let mut schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object", "properties": self.properties, "required": self.required,
            "additionalProperties": false,
        });
        if !conditional.is_empty() {
            schema["allOf"] = conditional.into();
        }
        let schema = schema::with_definitions(schema, self.generator.definitions());
        schema::check(&schema)?;
        Ok(InputSpec {
            ui: self.ui.finish(root)?,
            schema,
            fields: self.fields,
        })
    }
}

pub struct FieldBuilder<'a> {
    owner: &'a mut InputSpecBuilder,
    key: String,
    label: String,
    base_schema: JsonValue,
    choices: Vec<Choice>,
    item_choices: Vec<Choice>,
}

impl FieldBuilder<'_> {
    fn schema(&mut self) -> &mut JsonValue {
        self.owner
            .properties
            .get_mut(&self.key)
            .expect("field is registered at declaration")
    }

    pub fn optional(self) -> Self {
        self.owner.required.retain(|key| key != &self.key);
        self
    }

    /// Requires this field when `field` matches one of `values`; otherwise omission is allowed.
    pub fn required_when<V: Into<JsonValue>>(
        self, field: impl Into<String>, values: impl IntoIterator<Item = V>,
    ) -> Self {
        let this = self.optional();
        this.owner.conditions.push((
            field.into(),
            values.into_iter().map(Into::into).collect(),
            json!({"required": [this.key]}),
        ));
        this
    }

    /// When `field` matches one of `values`, supplied text must contain a non-whitespace character.
    /// Combine with `required_when` to also reject omission under the same condition.
    pub fn non_blank_when<V: Into<JsonValue>>(
        self, field: impl Into<String>, values: impl IntoIterator<Item = V>,
    ) -> Self {
        if self.base_schema["type"] != "string" {
            self.owner.errors.push(format!("{} is not a string", self.key));
        }
        self.owner.conditions.push((
            field.into(),
            values.into_iter().map(Into::into).collect(),
            json!({"properties": {&self.key: {"pattern": schema::NON_BLANK}}}),
        ));
        self
    }

    pub fn min_len(self, value: usize) -> Self {
        self.length(value, true)
    }

    pub fn max_len(self, value: usize) -> Self {
        self.length(value, false)
    }

    fn length(mut self, value: usize, minimum: bool) -> Self {
        let keys = match self.base_schema["type"].as_str() {
            Some("string") => ("minLength", "maxLength"),
            Some("array") => ("minItems", "maxItems"),
            Some("object") => ("minProperties", "maxProperties"),
            _ => {
                self.owner.errors.push(format!("{} has no length constraint", self.key));
                return self;
            }
        };
        let keyword = if minimum { keys.0 } else { keys.1 };
        let value = self.base_schema[keyword].as_u64().map_or(value as u64, |bound| {
            if minimum {
                bound.max(value as u64)
            } else {
                bound.min(value as u64)
            }
        });
        self.schema()[keyword] = value.into();
        if let (Some(min), Some(max)) = (self.schema()[keys.0].as_u64(), self.schema()[keys.1].as_u64()) &&
            min > max
        {
            self.owner
                .errors
                .push(format!("{} has inconsistent length bounds", self.key));
        }
        self
    }

    fn pattern(mut self, pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        if self.base_schema["type"] != "string" || schema::compile_pattern(&pattern).is_err() {
            self.owner
                .errors
                .push(format!("{} has an invalid string pattern", self.key));
        }
        if let Some(original) = self.base_schema.get("pattern").filter(|original| *original != &pattern) {
            let constraint = json!({"pattern": original});
            let constraints = self
                .schema()
                .as_object_mut()
                .unwrap()
                .entry("allOf")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .unwrap();
            if !constraints.contains(&constraint) {
                constraints.push(constraint);
            }
        }
        self.schema()["pattern"] = pattern.into();
        self
    }

    pub fn non_blank(self) -> Self {
        self.pattern(schema::NON_BLANK)
    }

    pub fn min(self, value: impl Into<JsonValue>) -> Self {
        self.bound("minimum", value.into())
    }

    pub fn max(self, value: impl Into<JsonValue>) -> Self {
        self.bound("maximum", value.into())
    }

    fn bound(mut self, keyword: &str, value: JsonValue) -> Self {
        if !matches!(self.base_schema["type"].as_str(), Some("integer" | "number")) ||
            schema::validate(&self.base_schema, &value, &self.key).is_err()
        {
            self.owner
                .errors
                .push(format!("{} has an invalid numeric bound", self.key));
        }
        self.schema()[keyword] = value;
        let property = self.schema();
        if let (Some(min), Some(max)) = (property["minimum"].as_number(), property["maximum"].as_number()) &&
            schema::compare_numbers(min, max).is_gt()
        {
            self.owner
                .errors
                .push(format!("{} has inconsistent numeric bounds", self.key));
        }
        self
    }

    /// Constrains the complete field value. Use `item_choices(...)` for a multi-select's options.
    pub fn choices<V: Into<JsonValue>, L: Into<String>>(mut self, choices: impl IntoIterator<Item = (V, L)>) -> Self {
        self.choices = build_choices(&self.base_schema, choices, &self.key, &mut self.owner.errors);
        self.schema()["enum"] = self.choices.iter().map(|choice| choice.value.clone()).collect();
        self
    }

    /// Constrains each list element and supplies its multi-select option label.
    pub fn item_choices<V: Into<JsonValue>, L: Into<String>>(
        mut self, choices: impl IntoIterator<Item = (V, L)>,
    ) -> Self {
        if self.base_schema["type"] != "array" || self.base_schema.get("prefixItems").is_some() {
            self.owner.errors.push(format!("{} is not a list", self.key));
            return self;
        }
        let mut items = schemars::Schema::try_from(self.base_schema.get("items").cloned().unwrap_or(json!(true)))
            .expect("generated item schema is an object or boolean");
        items.ensure_object();
        let mut items: JsonValue = items.into();
        self.item_choices = build_choices(
            &schema::with_definitions(items.clone(), self.owner.generator.definitions()),
            choices,
            "list item",
            &mut self.owner.errors,
        );
        items["enum"] = self.item_choices.iter().map(|choice| choice.value.clone()).collect();
        self.schema()["items"] = items;
        self
    }

    pub fn unique(mut self) -> Self {
        if self.base_schema["type"] != "array" {
            self.owner.errors.push(format!("{} is not a list", self.key));
        }
        self.schema()["uniqueItems"] = true.into();
        self
    }

    pub fn text_input(mut self) -> Node {
        self.checked_control(
            self.base_schema["type"] == "string",
            "text_input requires a string field",
            ui::Builder::text_input,
        )
    }

    pub fn text_area(mut self) -> Node {
        self.checked_control(
            self.base_schema["type"] == "string",
            "text_area requires a string field",
            ui::Builder::text_area,
        )
    }

    pub fn number_input(mut self) -> Node {
        self.checked_control(
            matches!(self.base_schema["type"].as_str(), Some("integer" | "number")),
            "number_input requires a numeric field",
            ui::Builder::number_input,
        )
    }

    pub fn toggle(mut self) -> Node {
        self.checked_control(
            self.base_schema["type"] == "boolean",
            "toggle requires a boolean field",
            ui::Builder::toggle,
        )
    }

    fn checked_control(
        &mut self, compatible: bool, requirement: &str, build: impl FnOnce(&ui::Builder, &str, &str) -> Node,
    ) -> Node {
        if !compatible {
            self.owner.errors.push(format!("{}: {requirement}", self.key));
        }
        build(&self.owner.ui, &self.key, &self.label)
    }

    pub fn select_one(self) -> Node {
        if !matches!(
            self.base_schema["type"].as_str(),
            Some("string" | "boolean" | "integer" | "number")
        ) || self.choices.is_empty()
        {
            self.owner
                .errors
                .push(format!("{}: select_one requires a scalar field with choices", self.key));
        }
        self.owner.ui.select_one(&self.key, &self.label, &self.choices)
    }

    pub fn select_many(self) -> Node {
        if self.base_schema["type"] != "array" || self.item_choices.is_empty() {
            self.owner.errors.push(format!(
                "{}: select_many requires a list field with item choices",
                self.key
            ));
        }
        self.owner.ui.select_many(&self.key, &self.label, &self.item_choices)
    }

    pub fn json_input(self) -> Node {
        self.owner.ui.json_input(&self.key, &self.label)
    }
}

fn build_choices<V: Into<JsonValue>, L: Into<String>>(
    schema: &JsonValue, choices: impl IntoIterator<Item = (V, L)>, context: &str, errors: &mut Vec<String>,
) -> Vec<Choice> {
    let choices: Vec<_> = choices
        .into_iter()
        .map(|(value, label)| Choice {
            value: value.into(),
            label: label.into(),
        })
        .collect();
    if choices.is_empty() ||
        choices
            .iter()
            .any(|choice| schema::validate(schema, &choice.value, context).is_err())
    {
        errors.push(format!("{context} has invalid choices"));
    }
    if choices.iter().enumerate().any(|(index, choice)| {
        choices[..index]
            .iter()
            .any(|previous| schema::equal(&previous.value, &choice.value))
    }) {
        errors.push(format!("{context} has duplicate choices"));
    }
    choices
}

pub(crate) fn escape_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use lyquid::prelude::new_hashmap;
    use lyquid_test::test;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use serde_json::{Value as JsonValue, json};

    use crate::{InputSpec, List, Mapping, Value, ui};

    macro_rules! json_value {
        ($ty:ty) => {
            impl Value for $ty {
                fn encode(&self) -> String {
                    serde_json::to_string(self).unwrap()
                }
                fn decode(&self, encoded: &str) -> Result<Box<dyn Value>, String> {
                    serde_json::from_str::<Self>(encoded)
                        .map(|value| Box::new(value) as Box<dyn Value>)
                        .map_err(|error| error.to_string())
                }
                fn clone_box(&self) -> Box<dyn Value> {
                    Box::new(self.clone())
                }
            }
        };
    }

    #[derive(Clone, Serialize, Deserialize, JsonSchema)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    #[schemars(rename = "Payload /~")]
    struct Payload {
        #[serde(rename(serialize = "output", deserialize = "answer"))]
        answer: String,
        optional_note: Option<String>,
        #[serde(default)]
        retries: u64,
        next: Option<Box<Payload>>,
    }
    json_value!(Payload);

    #[test]
    fn serde_fields_and_references() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut builder = InputSpec::builder();
        let custom = builder
            .field("custom", "Custom", CheckedText { calls: calls.clone() })
            .text_input();
        let prototype = Payload {
            answer: "prototype".into(),
            optional_note: None,
            retries: 0,
            next: None,
        };
        let payload = builder.field("payload", "Payload", prototype.clone()).json_input();
        let optional = builder.field("optional", "Optional", prototype).optional().json_input();
        let root = builder.ui().column(vec![custom, payload, optional]);
        let spec = builder.finish(root).unwrap();
        assert!(!spec.schema()["$defs"].as_object().unwrap().is_empty());
        assert!(
            spec.schema()["properties"]["payload"]["properties"]
                .get("answer")
                .is_some()
        );
        for payload in [
            json!({"output": "wrong direction"}),
            json!({"answer": "ok", "extra": true}),
            json!({"answer": "ok", "next": {"answer": 42}}),
            json!({"answer": "ok", "optionalNote": 42}),
            json!({"answer": "ok", "retries": -1}),
        ] {
            assert!(
                spec.decode_values(&json!({"custom": "ok", "payload": payload}))
                    .is_err()
            );
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        }
        let decoded = spec
            .decode_values(&json!({
                "custom": "ok", "payload": {"answer": "yes", "optionalNote": null, "next": {"answer": "nested"}}
            }))
            .unwrap();
        let payload: &dyn Any = decoded["payload"].as_ref();
        let payload = payload.downcast_ref::<Payload>().unwrap();
        assert_eq!(payload.answer, "yes");
        assert_eq!(payload.next.as_ref().unwrap().answer, "nested");
        assert_eq!(payload.retries, 0);
        assert!(payload.optional_note.is_none());
        assert!(!decoded.contains_key("optional"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[derive(Clone, Serialize, Deserialize, JsonSchema)]
    struct Digits(#[schemars(length(min = 2, max = 4), regex(pattern = "^[0-9]+$"))] String);
    json_value!(Digits);

    #[test]
    fn pattern_semantics() {
        #[derive(Deserialize)]
        struct Case {
            pattern: String,
            value: String,
            valid: bool,
        }
        // Expected results match JavaScript's new RegExp(pattern, "u").test(value).
        let cases: Vec<Case> = serde_json::from_str(
            r#"[
                {"pattern": "^\\d+$", "value": "123", "valid": true},
                {"pattern": "^\\d+$", "value": "\u0661\u0662", "valid": false},
                {"pattern": "^\\d+$", "value": "\uff11\uff12", "valid": false},
                {"pattern": "^\\D+$", "value": "\u0661\u0662", "valid": true},
                {"pattern": "^\\w+$", "value": "Az_9", "valid": true},
                {"pattern": "^\\w+$", "value": "\u00e9", "valid": false},
                {"pattern": "^\\W+$", "value": "\u00e9", "valid": true},
                {"pattern": "^\\s$", "value": "\ufeff", "valid": true},
                {"pattern": "^\\s$", "value": "\u0085", "valid": false},
                {"pattern": "^\\s$", "value": "\u2003", "valid": true},
                {"pattern": "^\\S$", "value": "\ufeff", "valid": false},
                {"pattern": "^\\S$", "value": "\u0085", "valid": true},
                {"pattern": "^.$", "value": "\n", "valid": false},
                {"pattern": "^.$", "value": "\r", "valid": false},
                {"pattern": "^.$", "value": "\u2028", "valid": false},
                {"pattern": "^.$", "value": "\u2029", "valid": false},
                {"pattern": "^.$", "value": "\ud83d\ude00", "valid": true},
                {"pattern": "^.$", "value": "ab", "valid": false},
                {"pattern": "a$", "value": "a\n", "valid": false},
                {"pattern": "a$", "value": "a", "valid": true},
                {"pattern": "42", "value": "x42y", "valid": true},
                {"pattern": "(?=a)a", "value": "a", "valid": true},
                {"pattern": "(?<=a)b", "value": "ab", "valid": true},
                {"pattern": "^(a)\\1$", "value": "aa", "valid": true},
                {"pattern": "^(a)\\1$", "value": "ab", "valid": false},
                {"pattern": "^\\p{L}+$", "value": "\u4e2d\u6587", "valid": true},
                {"pattern": "^\\p{L}+$", "value": "12", "valid": false},
                {"pattern": "^\\uD83D\\uDE00$", "value": "\ud83d\ude00", "valid": true}
            ]"#,
        )
        .unwrap();
        for case in cases {
            let mut builder = InputSpec::builder();
            let field = builder
                .field("text", "Text", String::new())
                .pattern(&case.pattern)
                .text_input();
            let spec = builder.finish(field).unwrap();
            assert_eq!(spec.field_schema("text").unwrap()["pattern"], case.pattern);
            assert_eq!(
                spec.decode_values(&json!({"text": case.value})).is_ok(),
                case.valid,
                "pattern {:?}, value {:?}",
                case.pattern,
                case.value,
            );
        }
    }

    #[derive(Clone, Serialize, Deserialize, JsonSchema)]
    struct RustPattern(#[schemars(regex(pattern = r"\Atext\z"))] String);
    json_value!(RustPattern);

    #[test]
    fn rejects_rust_pattern() {
        let mut builder = InputSpec::builder();
        let field = builder.field("text", "Text", RustPattern(String::new())).text_input();
        let error = builder.finish(field).err().unwrap();
        assert!(error.contains("invalid ECMAScript pattern"));
    }

    #[test]
    fn preserves_derived_constraints() {
        let mut builder = InputSpec::builder();
        let digits = builder
            .field("digits", "Digits", Digits("12".into()))
            .min_len(1)
            .max_len(8)
            .non_blank()
            .text_input();
        let spec = builder.finish(digits).unwrap();
        assert!(spec.decode(r#"{"digits":"123"}"#).is_ok());
        for digits in ["1", "12345", "ab", "  "] {
            assert!(spec.decode_values(&json!({"digits": digits})).is_err());
        }
    }

    #[test]
    #[allow(
        dead_code,
        reason = "These fixtures exercise schema derivation without constructing values."
    )]
    fn enum_representations() {
        #[derive(JsonSchema)]
        #[serde(untagged)]
        enum Untagged {
            Text(String),
            Pair(u64, bool),
        }
        #[derive(JsonSchema)]
        #[serde(tag = "kind", content = "data", rename_all = "snake_case", deny_unknown_fields)]
        enum Adjacent {
            Pair(u64, bool),
            Done,
        }
        #[derive(JsonSchema)]
        enum External {
            Text(String),
            Done,
        }

        fn check<T: JsonSchema>(accepted: &[JsonValue], rejected: &[JsonValue]) {
            let mut generator = super::schema::generator();
            let schema = super::schema::generate::<T>(&mut generator);
            let schema = super::schema::with_definitions(schema, generator.definitions());
            super::schema::check(&schema).unwrap();
            for value in accepted {
                assert!(
                    super::schema::validate(&schema, value, "input").is_ok(),
                    "rejected {value}"
                );
            }
            for value in rejected {
                assert!(
                    super::schema::validate(&schema, value, "input").is_err(),
                    "accepted {value}"
                );
            }
        }
        check::<Untagged>(
            &[json!("text"), json!([4, true])],
            &[json!([4]), json!([-1, true]), json!([4, true, 0])],
        );
        check::<Adjacent>(
            &[json!({"kind": "pair", "data": [4, true]}), json!({"kind": "done"})],
            &[
                json!({"kind": "other"}),
                json!({"kind": "pair", "data": [4, 0]}),
                json!({"kind": "done", "extra": 1}),
            ],
        );
        check::<External>(
            &[json!("Done"), json!({"Text": "hello"})],
            &[json!("Other"), json!({"Text": 1})],
        );
    }

    #[test]
    fn rejects_unsupported_schemas() {
        #[derive(Clone, JsonSchema)]
        #[schemars(with = "String", extend("contentSchema" = false))]
        struct Unsupported;
        impl Value for Unsupported {
            fn encode(&self) -> String {
                panic!("prototype must not be encoded")
            }
            fn decode(&self, _: &str) -> Result<Box<dyn Value>, String> {
                panic!("invalid schema must not reach decoding")
            }
            fn clone_box(&self) -> Box<dyn Value> {
                Box::new(self.clone())
            }
        }
        let mut builder = InputSpec::builder();
        let field = builder.field("value", "Value", Unsupported).text_input();
        assert!(builder.finish(field).err().unwrap().contains("contentSchema"));
        for schema in [
            json!({"$ref": "https://example.com/schema"}),
            json!({"$ref": "#/$defs/missing"}),
        ] {
            assert!(super::schema::check(&schema).is_err());
        }
    }

    fn form() -> InputSpec {
        let mut builder = InputSpec::builder();
        let heading = builder.ui().text("Send a gift");
        let recipient = builder
            .field("recipient", "Recipient", "prototype is not a draft".to_owned())
            .min_len(1)
            .max_len(50)
            .text_input();
        let preferences = builder
            .field("preferences", "Preferences", List::<String>(vec![]))
            .item_choices([("quiet", "Quiet"), ("portable", "Portable")])
            .unique()
            .min_len(1)
            .max_len(2)
            .select_many();
        let submit = builder.submit("Continue");
        let ui = builder.ui();
        let layout = ui.card(ui.column(vec![heading, ui.row(vec![recipient, preferences]), submit]));
        builder.finish(layout).unwrap()
    }

    #[test]
    fn json_input_rebuilds_schema_checked_json_decoders() {
        let encoded = serde_json::to_string(&form()).unwrap();
        let spec: InputSpec = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            serde_json::from_str::<JsonValue>(&encoded).unwrap()
        );
        let values = json!({"recipient": "Alex", "preferences": ["portable"]});
        let decoded = spec.decode_values(&values).unwrap();
        for (name, value) in values.as_object().unwrap() {
            let decoded: &dyn Any = decoded[name].as_ref();
            assert_eq!(decoded.downcast_ref::<JsonValue>(), Some(value));
        }
        for values in [
            json!({"recipient": "Alex", "preferences": ["portable", "portable"]}),
            json!({"recipient": "Alex", "preferences": [12]}),
            json!({"recipient": "", "preferences": ["quiet"]}),
            json!({"preferences": ["quiet"]}),
            json!({"recipient": "Alex", "preferences": ["quiet"], "unknown": true}),
        ] {
            assert!(spec.decode_values(&values).is_err(), "accepted {values}");
        }
        assert!(
            spec.decode(r#"{"recipient":"A","recipient":"B","preferences":["quiet"]}"#)
                .is_err()
        );
    }

    #[test]
    fn json_input_rejects_invalid_contracts() {
        let original = serde_json::to_value(form()).unwrap();
        for (pointer, value) in [
            ("/ui/root", json!("missing")),
            ("/ui/components/0/component", json!("UnknownWidget")),
            ("/schema/type", json!("array")),
            ("/schema/additionalProperties", json!(true)),
            ("/schema/properties", json!([])),
            ("/schema/properties", json!({"": {"type": "string"}})),
            (
                "/schema/properties/recipient",
                json!({"type": "string", "pattern": "["}),
            ),
            (
                "/schema/properties/recipient",
                json!({"$ref": "https://example.com/schema"}),
            ),
            ("/schema/properties/recipient", json!({"unsupported": true})),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(
                serde_json::from_value::<InputSpec>(invalid).is_err(),
                "accepted {pointer}"
            );
        }
        let mut invalid = original.clone();
        invalid["fields"] = json!({"recipient": "pretend decoder"});
        assert!(serde_json::from_value::<InputSpec>(invalid).is_err());
        for event in [json!("submit"), json!({"name": "submit", "context": "invalid"})] {
            let mut invalid = original.clone();
            let button = invalid["ui"]["components"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|component| component["component"] == "Button")
                .unwrap();
            button["action"]["event"] = event;
            assert!(serde_json::from_value::<InputSpec>(invalid).is_err());
        }
        let mut invalid = original;
        invalid["ui"]["components"][1]["id"] = invalid["ui"]["components"][0]["id"].clone();
        assert!(serde_json::from_value::<InputSpec>(invalid).is_err());
    }

    #[test]
    fn json_input_rejects_malformed_layout_children() {
        let original = serde_json::to_value(form()).unwrap();
        for (kind, key) in [
            ("Column", "children"),
            ("Row", "children"),
            ("Card", "child"),
            ("Button", "child"),
        ] {
            for value in [
                None,
                Some(JsonValue::Null),
                Some(json!(false)),
                Some(json!(1)),
                Some(json!({})),
                Some(json!([null])),
                Some(json!(["missing"])),
                Some(json!("missing")),
            ] {
                let mut encoded = original.clone();
                let component = encoded["ui"]["components"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|component| component["component"] == kind)
                    .unwrap();
                component.as_object_mut().unwrap().remove(key);
                if let Some(value) = &value {
                    component[key] = value.clone();
                }
                assert!(
                    serde_json::from_value::<InputSpec>(encoded).is_err(),
                    "accepted {kind}.{key} = {value:?}"
                );
            }
        }
    }

    #[test]
    fn json_input_preserves_empty_layouts() {
        for kind in ["Column", "Row"] {
            let mut encoded = serde_json::to_value(form()).unwrap();
            encoded["ui"]["components"] = json!([{"id": "root", "component": kind, "children": []}]);
            let spec: InputSpec = serde_json::from_value(encoded.clone()).unwrap();
            assert_eq!(serde_json::to_value(&spec).unwrap(), encoded);
            let surface = spec.ui().surface("input", Some("request")).unwrap();
            assert_eq!(
                surface[1]["updateComponents"]["components"],
                encoded["ui"]["components"]
            );
        }
    }

    #[test]
    fn json_input_rejects_malformed_button_actions() {
        for action in [
            JsonValue::Null,
            json!("submit"),
            json!([]),
            json!({}),
            json!({"event": "submit"}),
            json!({"event": {"context": {}}}),
            json!({"event": {"name": 1, "context": {}}}),
            json!({"event": {"name": "unknown", "context": {}}}),
            json!({"event": {"name": "submit"}}),
            json!({"event": {"name": "submit", "context": []}}),
            json!({"functionCall": "openUrl"}),
            json!({"functionCall": {"args": {"url": "https://example.com"}}}),
            json!({"functionCall": {"call": "unknown", "args": {"url": "https://example.com"}}}),
            json!({"functionCall": {"call": "openUrl"}}),
            json!({"functionCall": {"call": "openUrl", "args": "https://example.com"}}),
            json!({"functionCall": {"call": "openUrl", "args": {"url": false}}}),
            json!({"functionCall": {"call": "openUrl", "args": {"url": {"path": 1}}}}),
            json!({
                "event": {"name": "submit", "context": {}},
                "functionCall": {"call": "openUrl", "args": {"url": "https://example.com"}}
            }),
        ] {
            let mut encoded = serde_json::to_value(form()).unwrap();
            let button = encoded["ui"]["components"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|component| component["component"] == "Button")
                .unwrap();
            button["action"] = action.clone();
            assert!(
                serde_json::from_value::<InputSpec>(encoded).is_err(),
                "accepted {action}"
            );
        }
    }

    #[test]
    fn json_input_preserves_supported_button_actions() {
        for action in [
            json!({"event": {"name": "submit", "context": {}}}),
            json!({"functionCall": {"call": "openUrl", "args": {"url": "https://example.com"}}}),
            json!({"functionCall": {"call": "openUrl", "args": {"url": {"path": "/url"}}, "returnType": "void"}}),
        ] {
            let mut encoded = serde_json::to_value(form()).unwrap();
            encoded["ui"]["data"]["url"] = json!("https://example.com");
            let button = encoded["ui"]["components"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|component| component["component"] == "Button")
                .unwrap();
            button["action"] = action.clone();
            let spec: InputSpec = serde_json::from_value(encoded.clone()).unwrap();
            assert_eq!(serde_json::to_value(&spec).unwrap(), encoded);
            let surface = spec.ui().surface("input", Some("request")).unwrap();
            let button = surface[1]["updateComponents"]["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|component| component["component"] == "Button")
                .unwrap();
            if action.get("event").is_some() {
                assert_eq!(button["action"]["event"]["name"], "submit");
                assert_eq!(button["action"]["event"]["context"]["request_id"], "request");
            } else {
                assert_eq!(button["action"], action);
            }
        }
    }

    #[test]
    fn json_input_rejects_custom_ui_roots() {
        for components in [
            json!([{"id": "page", "component": "Column", "children": []}]),
            json!([
                {"id": "page", "component": "Column", "children": []},
                {"id": "root", "component": "Column", "children": []}
            ]),
        ] {
            let mut encoded = serde_json::to_value(form()).unwrap();
            encoded["ui"] = json!({"root": "page", "components": components, "data": {}});
            let error = serde_json::from_value::<InputSpec>(encoded).err().unwrap();
            assert!(error.to_string().contains("the UI root ID must be \"root\""), "{error}");
        }
    }

    #[test]
    fn json_input_rejects_cyclic_ui_components() {
        for components in [
            json!([{"id": "root", "component": "Column", "children": ["root"]}]),
            json!([{"id": "root", "component": "Card", "child": "root"}]),
            json!([
                {"id": "root", "component": "Column", "children": ["a"]},
                {"id": "a", "component": "Row", "children": ["root"]}
            ]),
            json!([
                {"id": "a", "component": "Card", "child": "b"},
                {"id": "root", "component": "Column", "children": ["a"]},
                {"id": "b", "component": "Row", "children": ["a"]}
            ]),
            json!([
                {"id": "root", "component": "Column", "children": []},
                {"id": "a", "component": "Card", "child": "b"},
                {"id": "b", "component": "Card", "child": "a"}
            ]),
        ] {
            let mut encoded = serde_json::to_value(form()).unwrap();
            encoded["ui"]["root"] = json!("root");
            encoded["ui"]["components"] = components;
            let error = serde_json::from_value::<InputSpec>(encoded).err().unwrap();
            assert!(error.to_string().contains("cyclic UI component references"), "{error}");
        }
    }

    #[test]
    fn json_input_preserves_shared_ui_children() {
        let mut encoded = serde_json::to_value(form()).unwrap();
        encoded["ui"] = json!({
            "root": "root",
            "components": [
                {"id": "text", "component": "Text", "text": "Shared"},
                {"id": "root", "component": "Column", "children": ["left", "right"]},
                {"id": "left", "component": "Card", "child": "text"},
                {"id": "right", "component": "Row", "children": ["text", "text"]}
            ],
            "data": {}
        });
        let spec: InputSpec = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(&spec).unwrap(), encoded);
        let surface = spec.ui().surface("input", Some("request")).unwrap();
        assert_eq!(
            surface[1]["updateComponents"]["components"],
            encoded["ui"]["components"]
        );
    }

    #[test]
    fn json_input_preserves_nested_values_and_number_types() {
        let mut encoded = serde_json::to_value(form()).unwrap();
        encoded["schema"] = json!({
            "type": "object", "additionalProperties": false,
            "properties": {
                "count": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                "payload": {
                    "type": "object", "additionalProperties": false,
                    "properties": {"enabled": {"type": "boolean"}, "note": {"type": ["string", "null"]}},
                    "required": ["enabled", "note"]
                }
            },
            "required": ["count", "payload"]
        });
        let spec: InputSpec = serde_json::from_value(encoded).unwrap();
        let values = json!({"count": u64::MAX, "payload": {"enabled": true, "note": null}});
        let decoded = spec.decode_values(&values).unwrap();
        assert_eq!(decoded["count"].encode(), u64::MAX.to_string());
        assert_eq!(
            serde_json::from_str::<JsonValue>(&decoded["payload"].encode()).unwrap(),
            values["payload"]
        );
        for invalid in [json!("42"), json!(-1), json!(1.5)] {
            let mut values = values.clone();
            values["count"] = invalid;
            assert!(spec.decode_values(&values).is_err());
        }
    }

    #[test]
    fn json_input_rejects_non_descending_reference_cycles() {
        let base = json!({"type": "object", "additionalProperties": false, "properties": {}});
        let mut schemas = vec![];
        let mut direct = base.clone();
        direct["$ref"] = json!("#");
        schemas.push(direct);
        let mut mutual = base.clone();
        mutual["$ref"] = json!("#/$defs/a");
        mutual["$defs"] = json!({
            "a": {"$ref": "#/$defs/b"},
            "b": {"$ref": "#%2F$defs%2Fa"}
        });
        schemas.push(mutual);
        for keyword in ["allOf", "anyOf", "oneOf", "not", "if", "then", "else"] {
            let mut schema = base.clone();
            schema[keyword] = if matches!(keyword, "allOf" | "anyOf" | "oneOf") {
                json!([{"$ref": "#"}])
            } else {
                json!({"$ref": "#"})
            };
            schemas.push(schema);
        }
        // A cycle in a field's schema must also be rejected, even though reaching the field
        // itself descends into a child input value.
        let mut nested = base;
        nested["properties"]["loop"] = json!({"$ref": "#/properties/loop"});
        schemas.push(nested);
        for schema in schemas {
            let mut encoded = serde_json::to_value(form()).unwrap();
            encoded["schema"] = schema;
            let error = serde_json::from_value::<InputSpec>(encoded).err().unwrap();
            assert!(error.to_string().contains("cyclic schema reference"), "{error}");
        }
    }

    #[test]
    fn json_input_preserves_shared_references_and_recursive_data() {
        let mut encoded = serde_json::to_value(form()).unwrap();
        encoded["schema"] = json!({
            "type": "object", "additionalProperties": false,
            "properties": {
                "left": {"$ref": "#/$defs/node"},
                "right": {"allOf": [{"$ref": "#/$defs/node"}, {"$ref": "#%2F$defs%2Fnode"}]}
            },
            "required": ["left", "right"],
            "$defs": {
                "node": {
                    "type": "object", "additionalProperties": false,
                    "properties": {
                        "value": {"type": "integer", "minimum": 0},
                        "children": {"type": "array", "items": {"$ref": "#/$defs/node"}},
                        "next": {"$ref": "#/$defs/node"}
                    },
                    "required": ["value", "children"]
                }
            }
        });
        let spec: InputSpec = serde_json::from_value(encoded).unwrap();
        let leaf = json!({"value": 2, "children": []});
        let mut input = json!({
            "left": {"value": 1, "children": [leaf], "next": leaf},
            "right": leaf
        });
        let decoded = spec.decode_values(&input).unwrap();
        assert_eq!(
            serde_json::from_str::<JsonValue>(&decoded["left"].encode()).unwrap(),
            input["left"]
        );
        input["left"]["children"][0]["value"] = json!(-1);
        assert_eq!(spec.decode_values(&input).err().unwrap().path, "/left/children/0/value");

        // Each next property and $ref adds an evaluation, exceeding the formatter's limit
        // while remaining within the JSON decoder's nesting limit.
        let mut deep = leaf;
        for _ in 0..80 {
            deep = json!({"value": 1, "children": [], "next": deep});
        }
        input["left"] = deep;
        let decoded = spec.decode_values(&input).unwrap();
        assert_eq!(
            serde_json::from_str::<JsonValue>(&decoded["left"].encode()).unwrap(),
            input["left"]
        );
        let leaf_path = format!("/left{}/value", "/next".repeat(80));
        *input.pointer_mut(&leaf_path).unwrap() = json!(-1);
        let error = spec.decode_values(&input).err().unwrap();
        assert_eq!(error.path, leaf_path);
        assert_eq!(error.message, "value violates minimum");
    }

    #[test]
    fn typed_field_schema_and_ui() {
        let spec = form();
        assert_eq!(spec.schema()["properties"]["preferences"]["items"]["type"], "string");
        assert_eq!(
            spec.schema()["properties"]["preferences"]["items"]["enum"],
            json!(["quiet", "portable"])
        );
        assert_eq!(spec.schema()["properties"]["preferences"]["uniqueItems"], true);
        let exported = serde_json::to_value(&spec).unwrap();
        assert!(exported.get("fields").is_none());
        assert!(!exported.to_string().contains("prototype is not a draft"));
        assert!(exported["ui"]["data"].get("fields").is_none());
        assert!(
            spec.ui().components().iter().any(
                |component| component["component"] == "ChoicePicker" && component["variant"] == "multipleSelection"
            )
        );
        assert_eq!(spec.ui().root(), "root");
        let decoded = spec
            .decode_values(&json!({"recipient": "A", "preferences": ["portable"]}))
            .unwrap();
        let preferences: &dyn Any = decoded["preferences"].as_ref();
        assert_eq!(preferences.downcast_ref::<List<String>>().unwrap().0, ["portable"]);
        for values in [
            json!({"recipient": "A", "preferences": []}),
            json!({"recipient": "A", "preferences": ["portable", "portable"]}),
            json!({"recipient": "A", "preferences": ["loud"]}),
            json!({"recipient": "A", "preferences": [12]}),
            json!({"recipient": "", "preferences": ["quiet"]}),
            json!({"recipient": "A", "preferences": ["quiet"], "unknown": true}),
        ] {
            assert!(spec.decode_values(&values).is_err(), "accepted {values}");
        }
    }

    #[test]
    fn untyped_item_choices() {
        #[derive(Clone, Serialize, Deserialize, JsonSchema)]
        struct Items(Vec<JsonValue>);
        json_value!(Items);

        let mut builder = InputSpec::builder();
        let field = builder
            .field("values", "Values", Items(vec![]))
            .item_choices([(json!(true), "Yes"), (json!(1), "One")])
            .select_many();
        let spec = builder.finish(field).unwrap();
        assert!(spec.decode(r#"{"values":[true,1]}"#).is_ok());
        assert!(spec.decode(r#"{"values":[false]}"#).is_err());
    }

    #[test]
    fn nested_types_and_integer_bounds() {
        let mut builder = InputSpec::builder();
        let mapping = builder
            .field("counts", "Counts", Mapping::<List<u64>>(new_hashmap()))
            .json_input();
        let signed = builder.field("signed", "Signed", 0_i64).number_input();
        let enabled = builder.field("enabled", "Enabled", true).optional().toggle();
        let layout = builder.ui().column(vec![mapping, signed, enabled]);
        let spec = builder.finish(layout).unwrap();
        assert_eq!(
            spec.schema()["properties"]["counts"]["additionalProperties"]["items"]["type"],
            "integer"
        );
        let valid = json!({"counts": {"a": [u64::MAX]}, "signed": i64::MIN});
        let decoded = spec.decode_values(&valid).unwrap();
        let counts: &dyn Any = decoded["counts"].as_ref();
        assert_eq!(
            counts.downcast_ref::<Mapping<List<u64>>>().unwrap().0["a"].0,
            [u64::MAX]
        );
        assert!(!decoded.contains_key("enabled"));
        for values in [
            json!({"counts": {"a": [-1]}, "signed": 0}),
            json!({"counts": {"a": ["1"]}, "signed": 0}),
            json!({"counts": {}, "signed": u64::MAX}),
            json!({"counts": {}, "signed": 0, "enabled": null}),
            json!({"counts": {}, "signed": 0, "enabled": "true"}),
        ] {
            assert!(spec.decode_values(&values).is_err(), "accepted {values}");
        }
        assert!(spec.decode(r#"{"counts":{},"signed":9223372036854775808}"#).is_err());
        assert!(
            spec.decode(r#"{"counts":{"a":[18446744073709551616]},"signed":0}"#)
                .is_err()
        );
    }

    #[derive(Clone, schemars::JsonSchema)]
    #[schemars(with = "String")]
    struct CheckedText {
        calls: Arc<AtomicUsize>,
    }
    impl Value for CheckedText {
        fn encode(&self) -> String {
            panic!("the prototype must not be serialized to derive a type or default")
        }
        fn decode(&self, encoded: &str) -> Result<Box<dyn Value>, String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if encoded == r#""reject""# {
                return Err("custom validation".into());
            }
            Ok(Box::new(self.clone()))
        }
        fn clone_box(&self) -> Box<dyn Value> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn validates_before_decoding() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut builder = InputSpec::builder();
        let custom = builder
            .field("a", "Custom", CheckedText { calls: calls.clone() })
            .text_input();
        let number = builder.field("b", "Number", 0_u64).min(2).max(5).number_input();
        let omitted = builder
            .field("c", "Optional", CheckedText { calls: calls.clone() })
            .optional()
            .text_input();
        let layout = builder.ui().column(vec![custom, number, omitted]);
        let spec = builder.finish(layout).unwrap();
        assert!(spec.decode(r#"{"a":"ok","b":7}"#).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(spec.decode(r#"{"a":"reject","b":3}"#).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let decoded = spec.decode(" {\"a\":\"ok\",\"b\":3} \n").unwrap();
        let custom: &dyn Any = decoded["a"].as_ref();
        assert!(custom.downcast_ref::<CheckedText>().is_some());
        assert!(!decoded.contains_key("c"));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        for encoded in [
            r#"{"a":"ok","a":"reject","b":3}"#,
            r#"{"a":"ok","b":3} {}"#,
            r#"{"a":"ok","b":3} trailing"#,
        ] {
            assert!(spec.decode(encoded).is_err());
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
    }

    #[test]
    fn validates_hidden_fields() {
        let mut builder = InputSpec::builder();
        let action = builder
            .field("action", "Action", String::new())
            .choices([("refine", "Refine"), ("finish", "Finish")])
            .select_one();
        // Deliberately omit the feedback node from the root. Visibility cannot remove its contract.
        let _hidden = builder
            .field("feedback", "Feedback", String::new())
            .required_when("action", ["refine"])
            .non_blank_when("action", ["refine"])
            .text_area();
        let spec = builder.finish(action).unwrap();
        assert!(spec.decode(r#"{"action":"refine"}"#).is_err());
        assert!(spec.decode(r#"{"action":"refine","feedback":" \n\t"}"#).is_err());
        assert!(spec.decode(r#"{"action":"refine","feedback":"  useful  "}"#).is_ok());
        assert!(!spec.decode(r#"{"action":"finish"}"#).unwrap().contains_key("feedback"));
        assert!(spec.decode(r#"{"action":"finish","feedback":""}"#).is_ok());
        assert!(spec.decode(r#"{"action":"finish","feedback":null}"#).is_err());
    }

    #[test]
    fn combined_input_contract() {
        let build = |allow_finish| {
            let mut builder = InputSpec::builder();
            let mut choices = vec![("refine", "Refine"), ("restart", "Restart")];
            if allow_finish {
                choices.push(("finish", "Finish"));
            }
            let action = builder
                .field("action", "Action", String::new())
                .choices(choices)
                .select_one();
            let feedback = builder
                .field("feedback", "Feedback", String::new())
                .required_when("action", ["refine", "restart"])
                .non_blank_when("action", ["refine", "restart"])
                .text_area();
            let layout = builder.ui().column(vec![action, feedback]);
            builder.finish(layout).unwrap()
        };
        let spec = build(true);
        for encoded in [
            r#"{}"#,
            r#"{"action":"unknown","feedback":"text"}"#,
            r#"{"action":"refine"}"#,
            r#"{"action":"restart","feedback":" \n\t"}"#,
            r#"{"action":"refine","feedback":17}"#,
            r#"{"action":"finish","feedback":null}"#,
            r#"{"action":"finish","extra":true}"#,
            r#"{"action":"finish","action":"refine"}"#,
        ] {
            assert!(spec.decode(encoded).is_err(), "accepted {encoded}");
        }
        for (action, feedback) in [
            ("refine", "  light & portable  "),
            ("restart", "More options"),
            ("finish", ""),
        ] {
            let decoded = spec
                .decode_values(&json!({"action": action, "feedback": feedback}))
                .unwrap();
            let decoded_action: &dyn Any = decoded["action"].as_ref();
            let decoded_feedback: &dyn Any = decoded["feedback"].as_ref();
            assert_eq!(decoded_action.downcast_ref::<String>().unwrap(), action);
            assert_eq!(decoded_feedback.downcast_ref::<String>().unwrap(), feedback);
        }
        assert!(!spec.decode(r#"{"action":"finish"}"#).unwrap().contains_key("feedback"));
        let restricted = build(false);
        assert!(restricted.decode(r#"{"action":"finish"}"#).is_err());
        assert!(restricted.decode(r#"{"action":"refine","feedback":"lighter"}"#).is_ok());
        assert_eq!(
            restricted.schema()["properties"]["action"]["enum"],
            json!(["refine", "restart"])
        );
    }

    #[test]
    fn rejects_invalid_builders() {
        let mut duplicate = InputSpec::builder();
        let _first = duplicate.field("x", "X", String::new()).text_input();
        let second = duplicate.field("x", "X again", false).toggle();
        assert!(duplicate.finish(second).is_err());
        let mut limits = InputSpec::builder();
        let field = limits.field("x", "X", 0_u64).min(10).max(5).number_input();
        assert!(limits.finish(field).is_err());
        let mut condition = InputSpec::builder();
        let field = condition
            .field("x", "X", String::new())
            .required_when("missing", [true])
            .text_input();
        assert!(condition.finish(field).is_err());
        let invalid_controls: [fn(&mut crate::InputSpecBuilder) -> ui::Node; 8] = [
            |builder| builder.field("x", "X", false).text_input(),
            |builder| builder.field("x", "X", 0_u64).text_area(),
            |builder| builder.field("x", "X", String::new()).number_input(),
            |builder| builder.field("x", "X", String::new()).toggle(),
            |builder| builder.field("x", "X", String::new()).select_one(),
            |builder| {
                builder
                    .field("x", "X", List::<String>(vec![]))
                    .item_choices([("a", "A")])
                    .select_one()
            },
            |builder| builder.field("x", "X", List::<String>(vec![])).select_many(),
            |builder| {
                builder
                    .field("x", "X", String::new())
                    .choices([("a", "A")])
                    .select_many()
            },
        ];
        for build in invalid_controls {
            let mut builder = InputSpec::builder();
            let field = build(&mut builder);
            assert!(builder.finish(field).is_err());
        }
        let mut choices = InputSpec::builder();
        let field = choices
            .field("x", "X", String::new())
            .choices([("same", "One"), ("same", "Two")])
            .select_one();
        assert!(choices.finish(field).is_err());
        for values in [vec![], vec![json!("1")], vec![json!(1), json!(1.0)]] {
            let options = || values.iter().cloned().map(|value| (value, "Option"));
            let mut scalar = InputSpec::builder();
            let field = scalar.field("x", "X", 0_u64).choices(options()).number_input();
            assert!(scalar.finish(field).is_err());
            let mut list = InputSpec::builder();
            let field = list
                .field("x", "X", List::<u64>(vec![]))
                .item_choices(options())
                .json_input();
            assert!(list.finish(field).is_err());
        }
        let first = ui::Builder::default();
        let second = ui::Builder::default();
        assert!(
            first
                .finish(first.row(vec![first.text("A"), second.text("B")]))
                .is_err()
        );
    }

    #[test]
    fn replaces_choices() {
        let mut builder = InputSpec::builder();
        let scalar = builder
            .field("scalar", "Scalar", String::new())
            .choices([("old", "Old")])
            .choices([("new", "New")])
            .select_one();
        let list = builder
            .field("list", "List", List::<String>(vec![]))
            .item_choices([("old", "Old")])
            .item_choices([("new", "New")])
            .select_many();
        let layout = builder.ui().column(vec![scalar, list]);
        let spec = builder.finish(layout).unwrap();
        assert_eq!(spec.schema()["properties"]["scalar"]["enum"], json!(["new"]));
        assert_eq!(spec.schema()["properties"]["list"]["items"]["enum"], json!(["new"]));
        assert!(spec.decode_values(&json!({"scalar": "new", "list": ["new"]})).is_ok());
        for values in [
            json!({"scalar": "old", "list": ["new"]}),
            json!({"scalar": "new", "list": ["old"]}),
        ] {
            assert!(spec.decode_values(&values).is_err());
        }
        for component in spec
            .ui()
            .components()
            .iter()
            .filter(|c| c["component"] == "ChoicePicker")
        {
            assert_eq!(component["options"], json!([{"value": "\"new\"", "label": "New"}]));
        }
    }

    #[test]
    fn multiselect_item_choices() {
        let mut builder = InputSpec::builder();
        let field = builder
            .field("tags", "Tags", List::<String>(vec![]))
            .choices([(json!(["quiet"]), "Quiet set")])
            .select_many();
        assert!(builder.finish(field).is_err());

        for items_first in [false, true] {
            let mut builder = InputSpec::builder();
            let field = builder.field("tags", "Tags", List::<String>(vec![]));
            let field = if items_first {
                field
                    .item_choices([("quiet", "Quiet")])
                    .choices([(json!(["quiet"]), "Quiet set")])
            } else {
                field
                    .choices([(json!(["quiet"]), "Quiet set")])
                    .item_choices([("quiet", "Quiet")])
            };
            let field = field.select_many();
            let spec = builder.finish(field).unwrap();
            let picker = spec
                .ui()
                .components()
                .iter()
                .find(|c| c["component"] == "ChoicePicker")
                .unwrap();
            assert_eq!(picker["options"][0]["label"], "Quiet");
            let selected: JsonValue = serde_json::from_str(picker["options"][0]["value"].as_str().unwrap()).unwrap();
            let decoded = spec.decode_values(&json!({"tags": [selected]})).unwrap();
            let tags: &dyn Any = decoded["tags"].as_ref();
            assert_eq!(tags.downcast_ref::<List<String>>().unwrap().0, ["quiet"]);
            assert!(spec.decode_values(&json!({"tags": []})).is_err());
        }
    }

    #[test]
    fn empty_layout_ownership() {
        let mut builder = InputSpec::builder();
        let field = builder.field("text", "Text", String::new()).text_input();
        let ui = builder.ui();
        let layout = ui.column(vec![ui.column(vec![]), field, ui.card(ui.row(vec![]))]);
        let spec = builder.finish(layout).unwrap();
        assert!(spec.decode(r#"{"text":"hello"}"#).is_ok());
        for kind in ["Column", "Row"] {
            assert!(
                spec.ui()
                    .components()
                    .iter()
                    .any(|c| c["component"] == kind && c["children"] == json!([]))
            );
        }

        let ui = ui::Builder::default();
        assert!(ui.finish(ui.column(vec![])).is_ok());
        assert!(ui.finish(ui.row(vec![])).is_ok());
        let foreign = ui::Builder::default();
        assert!(ui.finish(ui.card(foreign.column(vec![]))).is_err());
    }

    struct AtomicStep {
        calls: Arc<AtomicUsize>,
        decodes: Arc<AtomicUsize>,
    }
    impl crate::Step for AtomicStep {
        fn description(&self, _: bool) -> String {
            "Atomic input test".into()
        }
        fn input(&self, _: &crate::Scope) -> Option<InputSpec> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut builder = InputSpec::builder();
            let a = builder.field("a", "A", String::new()).text_input();
            let b = builder
                .field(
                    "b",
                    "B",
                    CheckedText {
                        calls: self.decodes.clone(),
                    },
                )
                .text_input();
            let layout = builder.ui().column(vec![a, b]);
            Some(builder.finish(layout).unwrap())
        }
        fn model_template(&self, scope: &crate::Scope) -> crate::TemplateSpec {
            assert_eq!(scope.get::<String>(crate::StateNamespace::Input, "a").unwrap(), "value");
            assert!(scope.get::<CheckedText>(crate::StateNamespace::Input, "b").is_some());
            crate::TemplateSpec::Skip(crate::TurnProposal::Advance {
                next: Some("done".into()),
                updates: crate::StateUpdates::default(),
            })
        }
        fn finalize(
            &self, _: &crate::Scope, _: &mut crate::TurnProposal,
        ) -> Result<crate::TraceSummary, crate::FlowError> {
            Ok(crate::TraceSummary::Summary("Accepted both fields".into()))
        }
    }

    #[test]
    fn cooperative_decode_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let decodes = Arc::new(AtomicUsize::new(0));
        let flow = crate::Flow::builder("atomic")
            .entry("input")
            .exit("done")
            .step(
                "input",
                AtomicStep {
                    calls: calls.clone(),
                    decodes: decodes.clone(),
                },
            )
            .build()
            .unwrap();
        let mut scope = crate::Scope::new(
            Arc::new(flow),
            crate::State::default(),
            crate::AutoCheckpointConfig::Disabled,
            None,
        );
        let handle = scope.input_handle();
        let (spec, _) = scope.run_until_input().unwrap().unwrap();
        assert!(handle.submit_input(r#"{"a":"value","b":"reject"}"#).is_err());
        assert!(scope.get::<String>(crate::StateNamespace::Input, "a").is_none());
        assert!(scope.trace().entries.is_empty());
        let (again, _) = scope.run_until_input().unwrap().unwrap();
        assert_eq!(spec.schema(), again.schema());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(decodes.load(Ordering::Relaxed), 1);
        handle.submit_input(r#"{"a":"value","b":"ok"}"#).unwrap();
        assert_eq!(decodes.load(Ordering::Relaxed), 2);
        assert!(scope.trace().entries.is_empty());
        assert!(scope.get::<String>(crate::StateNamespace::Input, "a").is_none());
        assert!(scope.run_until_input().unwrap().is_none());
        assert_eq!(
            decodes.load(Ordering::Relaxed),
            2,
            "execution must not decode accepted input again"
        );
        assert_eq!(scope.trace().entries.len(), 1);
        assert!(scope.get::<String>(crate::StateNamespace::Input, "a").is_none());
        assert!(scope.get::<CheckedText>(crate::StateNamespace::Input, "b").is_none());
    }

    #[test]
    fn preserves_choice_types() {
        let choices = vec![
            ui::Choice {
                value: json!(true),
                label: "Boolean".into(),
            },
            ui::Choice {
                value: json!("true"),
                label: "String".into(),
            },
            ui::Choice {
                value: json!(42),
                label: "Number".into(),
            },
        ];
        let builder = ui::Builder::default();
        let field = builder.select_many("values", "Values", &choices);
        let document = builder.finish(field).unwrap();
        let component = document
            .components()
            .iter()
            .find(|component| component["component"] == "ChoicePicker")
            .unwrap();
        for (index, choice) in choices.iter().enumerate() {
            let encoded = component["options"][index]["value"].as_str().unwrap();
            assert_eq!(serde_json::from_str::<JsonValue>(encoded).unwrap(), choice.value);
        }
        assert_ne!(component["options"][0]["value"], component["options"][1]["value"]);
    }
    #[test]
    fn button_values() {
        let mut builder = InputSpec::builder();
        builder
            .field("action", "Action", String::new())
            .choices([("refine", "Refine")]);
        let button = builder.submit_with("Refine", [("action", "refine")]);
        let spec = builder.finish(button).unwrap();
        let messages = spec.ui().surface("input", Some("round")).unwrap();
        let button = messages[1]["updateComponents"]["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["component"] == "Button")
            .unwrap();
        assert_eq!(button["action"]["event"]["context"]["request_id"], "round");
        let path = button["action"]["event"]["context"]["values"]["path"].as_str().unwrap();
        assert_eq!(
            messages[2]["updateDataModel"]["value"].pointer(path).unwrap(),
            &json!({"action": "refine"})
        );
        for (field, value) in [("action", "unknown"), ("missing", "refine")] {
            let mut builder = InputSpec::builder();
            builder
                .field("action", "Action", String::new())
                .choices([("refine", "Refine")]);
            let button = builder.submit_with("Refine", [(field, value)]);
            assert!(builder.finish(button).is_err());
        }
    }
}
