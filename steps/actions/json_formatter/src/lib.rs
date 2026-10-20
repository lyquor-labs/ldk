//! Optional JSON parsing and validation actions for structured Steps.
//!
//! Parse a preceding text result or read the original model response from temporary action context.
//! Save the parsed value with `StructuredStepBuilder::action_named` to make it available to later actions and bindings.
//! These actions do not call a model, change its request, select a next Step, or write State.

use lyquid_flow::{check_json_schema, validate_json_schema};
use lyquid_llm::FinishReason;
use lyquid_structured_step::ActionContext;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Serializable settings owned by the JSON formatter action.
/// Omitting `schema` accepts any complete JSON value.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonFormatterConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Value>,
}

impl JsonFormatterConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn json_schema(schema: Value) -> Self {
        Self { schema: Some(schema) }
    }
}

/// Build an ordinary finalization action from JSON text to a validated JSON value.
/// Static schema errors fail here, before the action is attached or a model is called.
/// Pass the returned callback to `StructuredStepBuilder::action` or `StructuredStepBuilder::action_named`.
pub fn json_formatter<C>(
    config: JsonFormatterConfig,
) -> Result<impl Fn(&ActionContext<'_, C>, String) -> Result<Value, String> + Clone + Send + Sync, String> {
    let parse = json_parser(config)?;
    Ok(move |_: &ActionContext<'_, C>, text: String| parse(&text))
}

/// Parse the original model response from temporary action context, ignoring the previous result.
/// The response and all metadata remain available through `context.model_response()` at every position.
/// Use `action_named` to retain the formatted value independently of subsequent action results.
/// Flow's `ModelTemplate` response parser still runs before finalization.
pub fn model_response_json_formatter<C, P>(
    config: JsonFormatterConfig,
) -> Result<impl Fn(&ActionContext<'_, C>, P) -> Result<Value, String> + Clone + Send + Sync, String> {
    let parse = json_parser(config)?;
    Ok(move |context: &ActionContext<'_, C>, _: P| {
        let response = context.model_response().ok_or("action context has no model response")?;
        if response.finish_reason == Some(FinishReason::Length) {
            return Err("model response exceeded its output-token budget".into());
        }
        let text = response
            .text
            .as_ref()
            .ok_or_else(|| format!("model returned no text; finish={:?}", response.finish_reason))?;
        parse(text)
    })
}

fn json_parser(
    config: JsonFormatterConfig,
) -> Result<impl Fn(&str) -> Result<Value, String> + Clone + Send + Sync, String> {
    if let Some(schema) = &config.schema {
        check_json_schema(schema).map_err(|error| format!("invalid formatter schema: {error}"))?;
    }
    Ok(move |text: &str| {
        // Accept a complete JSON document optionally enclosed in one Markdown fence.
        let text = text.trim();
        let fence_length = text.bytes().take_while(|&byte| byte == b'`').count();
        let text = if fence_length >= 3 {
            let (tag, body) = text[fence_length..]
                .split_once('\n')
                .ok_or("JSON fence opening must end with a newline")?;
            if !matches!(tag.trim(), "" | "json") {
                return Err("JSON fence must be untagged or use the json tag".into());
            }
            let (body, closing_line) = body.rsplit_once('\n').ok_or("unclosed JSON fence")?;
            let closing = closing_line.trim_start_matches(' ');
            if closing_line.len() - closing.len() > 3 ||
                closing.len() < fence_length ||
                !closing.bytes().all(|byte| byte == b'`')
            {
                return Err(
                    "JSON closing fence must be on its own line with at least as many backticks as the opening".into(),
                );
            }
            body.trim()
        } else {
            text
        };
        let value = serde_json::from_str(text).map_err(|error| format!("decode JSON result: {error}"))?;
        if let Some(schema) = &config.schema {
            validate_json_schema(schema, &value, "result")?;
        }
        Ok(value)
    })
}

#[cfg(test)]
#[path = "../tests/formatting/mod.rs"]
mod formatting_tests;

#[cfg(test)]
#[path = "../tests/composition/mod.rs"]
mod composition_tests;
