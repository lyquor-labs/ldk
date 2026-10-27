use lyquid_llm::FinishReason;
use lyquid_test::test;
use serde_json::json;

use crate::composition_tests::response;
use crate::{JsonFormatterConfig, json_formatter, model_response_json_formatter};

#[test]
fn saved_configuration_round_trips_and_exports_its_schema() {
    let plain: JsonFormatterConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(plain, JsonFormatterConfig::new());
    assert_eq!(serde_json::to_value(plain).unwrap(), json!({}));
    let schema = json!({"type": "object", "required": ["answer"]});
    let config = JsonFormatterConfig::json_schema(schema.clone());
    let saved = serde_json::to_value(&config).unwrap();
    assert_eq!(saved, json!({"schema": schema}));
    assert_eq!(serde_json::from_value::<JsonFormatterConfig>(saved).unwrap(), config);
    assert!(serde_json::from_value::<JsonFormatterConfig>(json!({"name":"old"})).is_err());
    let config_schema = serde_json::to_value(schemars::schema_for!(JsonFormatterConfig)).unwrap();
    assert!(config_schema["properties"].get("schema").is_some());
}

#[test]
fn complete_json_values_and_fences_are_supported() {
    let format = json_formatter(JsonFormatterConfig::new()).unwrap();
    for text in ["null", "true", "7", "\"text\"", "[1,2]", "{\"answer\":42}"] {
        let expected = serde_json::from_str::<serde_json::Value>(text).unwrap();
        for wrapped in [
            format!("  {text}\n"),
            format!("```json\n{text}\n```"),
            format!("```\n{text}\n```"),
            format!("```json\r\n{text}\r\n```"),
            format!("```\r\n{text}\r\n```"),
        ] {
            assert_eq!(format(&wrapped).unwrap(), expected);
        }
    }
    for invalid in [
        "",
        "{",
        "{} {}",
        "Here is JSON: {}",
        "```json\n{}",
        "```json\n{}\n``` trailing",
    ] {
        assert!(format(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn fence_opening_requires_a_line_boundary_and_an_exact_json_tag() {
    let format = json_formatter(JsonFormatterConfig::new()).unwrap();
    for invalid in [
        "```json42```",
        "```jsontrue```",
        "```42```",
        "```json42\n```",
        "```json42\n42\n```",
        "```json5\n42\n```",
        "```javascript\n42\n```",
    ] {
        assert!(format(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn closing_fences_require_their_own_line_and_match_the_opening_length() {
    let format = json_formatter(JsonFormatterConfig::new()).unwrap();
    for invalid in [
        "```json\n42```",
        "```\n42 ```",
        "```json\n{\n\"answer\":42\n}```",
        "````json\n42````",
        "````json\n42\n```",
        "```json\n42\n``",
        "```json\n42\n``` extra",
        "```json\n42\n    ```",
        "```json\n42\n\t```",
    ] {
        assert!(format(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn longer_backtick_fences_allow_matching_or_longer_closing_lines() {
    let format = json_formatter(JsonFormatterConfig::new()).unwrap();
    for opening in [3, 4, 5] {
        for closing in [opening, opening + 1] {
            for tag in ["", "json"] {
                for newline in ["\n", "\r\n"] {
                    let text = format!(
                        "{}{tag}{newline}42{newline}   {} \t{newline}",
                        "`".repeat(opening),
                        "`".repeat(closing),
                    );
                    assert_eq!(format(&text).unwrap(), 42);
                }
            }
        }
    }
}

#[test]
fn schema_checks_structure_and_nested_constraints() {
    let format = json_formatter(JsonFormatterConfig::json_schema(json!({
        "type": "object",
        "properties": {
            "items": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/item"}},
            "route": {"enum": ["done", "again"]}
        },
        "required": ["items", "route"],
        "additionalProperties": false,
        "$defs": {"item": {"type": "integer", "minimum": 1}}
    })))
    .unwrap();
    assert_eq!(
        format(r#"{"items":[2],"route":"done"}"#).unwrap(),
        json!({"items":[2],"route":"done"})
    );
    for invalid in [
        json!({"items": [0], "route": "done"}),
        json!({"items": [], "route": "done"}),
        json!({"items": [1], "route": "unknown"}),
        json!({"items": [1]}),
        json!({"items": [1], "route": "done", "extra": true}),
    ] {
        assert!(format(&invalid.to_string()).is_err());
    }
}

#[test]
fn unsupported_schemas_fail_when_constructing_either_formatter() {
    for schema in [
        json!({"unsupported":true}),
        json!({"$ref":"https://example.com/schema"}),
        json!({"type":"unknown"}),
        json!({"$ref":"#"}),
    ] {
        assert!(json_formatter(JsonFormatterConfig::json_schema(schema.clone())).is_err());
        assert!(model_response_json_formatter(JsonFormatterConfig::json_schema(schema)).is_err());
    }
}

#[test]
fn recursive_schema_validation_keeps_the_formatter_evaluation_limit() {
    let format = json_formatter(JsonFormatterConfig::json_schema(json!({
        "type": "object", "properties": {"next": {"$ref": "#"}}
    })))
    .unwrap();
    let mut value = json!({});
    // Each property and $ref contributes one evaluation; 64 links reach the limit.
    for _ in 0..64 {
        value = json!({"next": value});
    }
    assert_eq!(format(&value.to_string()).unwrap(), value);
    value = json!({"next": value});
    let error = format(&value.to_string()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("schema validation exceeded 128 nested evaluations"),
        "{error}"
    );
}

#[test]
fn schema_composition_cannot_hide_the_formatter_evaluation_limit() {
    let recursive = json!({"$ref": "#/$defs/node"});
    let definitions = json!({"node": {"properties": {"next": {"$ref": "#/$defs/node"}}}});
    let mut value = json!({});
    for _ in 0..65 {
        value = json!({"next": value});
    }
    for (mut schema, accepts_shallow) in [
        (json!({"not": recursive}), false),
        (json!({"if": recursive, "then": false, "else": true}), false),
        (json!({"oneOf": [recursive, true]}), false),
        (json!({"anyOf": [recursive, true]}), true),
        (json!({"allOf": [recursive]}), true),
    ] {
        schema["$defs"] = definitions.clone();
        let format = json_formatter(JsonFormatterConfig::json_schema(schema.clone())).unwrap();
        assert_eq!(format("{}").is_ok(), accepts_shallow, "{schema}");
        let error = format(&value.to_string()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("schema validation exceeded 128 nested evaluations"),
            "{schema}: {error}"
        );
    }
}

#[test]
fn model_response_formatter_checks_presence_and_completion_before_parsing() {
    let format = model_response_json_formatter(JsonFormatterConfig::json_schema(json!({"type":"integer"}))).unwrap();
    let valid = response("42");
    let mut truncated = valid.clone();
    truncated.finish_reason = Some(FinishReason::Length);
    let mut missing = valid.clone();
    missing.text = None;
    assert_eq!(format(Some(&valid)).unwrap(), 42);
    for (raw, message) in [
        (None, "no model response"),
        (Some(&truncated), "output-token budget"),
        (Some(&missing), "no text"),
    ] {
        assert!(format(raw).unwrap_err().to_string().contains(message));
    }
    let wrong_type = response("\"wrong type\"");
    assert!(format(Some(&wrong_type)).is_err());
}

#[test]
fn model_response_formatter_preserves_the_response_and_all_metadata() {
    let format = model_response_json_formatter(JsonFormatterConfig::new()).unwrap();
    let original = response("  ```json\n{\"answer\":42}\n```  ");
    let expected = original.clone();
    let output = format(Some(&original)).unwrap();
    assert_eq!(output, json!({"answer": 42}));
    assert_eq!(original, expected);
}

#[test]
fn formatter_preserves_ecmascript_rules_and_error_paths() {
    let format = json_formatter(JsonFormatterConfig::json_schema(json!({
        "type": "object",
        "properties": {"answer": {"type": "string", "pattern": "^(?=A)[A-Z]+$"}},
        "required": ["answer"]
    })))
    .unwrap();
    assert_eq!(format(r#"{"answer":"ABC"}"#).unwrap(), json!({"answer":"ABC"}));
    for invalid in [r#"{"answer":"BCD"}"#, "{}"] {
        assert!(format(invalid).unwrap_err().to_string().contains("result/answer"));
    }
}
