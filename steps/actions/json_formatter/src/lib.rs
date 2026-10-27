//! JSON parsing and validation helpers for native Step finalizers.
//!
//! Parse text or pass `Scope::model_response()` to the response formatter. The caller owns any
//! proposed State updates, destination and Trace summary; Core validates and commits the turn.

use lyquid_flow::{FlowError, check_json_schema, validate_json_schema};
use lyquid_llm::{FinishReason, ModelResponse};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Optional schema used by the JSON formatter.
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

/// Builds a formatter for the original model response available during native Step finalization.
/// Pass `scope.model_response()` to the returned function. It borrows the response without
/// changing its text or metadata. Core's response parser still runs before finalization.
pub fn model_response_json_formatter(
    config: JsonFormatterConfig,
) -> Result<impl Fn(Option<&ModelResponse>) -> Result<Value, FlowError> + Clone + Send + Sync, FlowError> {
    let parse = json_formatter(config)?;
    Ok(move |response: Option<&ModelResponse>| {
        let response = response.ok_or("no model response")?;
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

/// Builds a formatter from JSON text to a validated JSON value.
/// Invalid schemas fail when constructing the formatter; malformed text or mismatched values
/// fail when calling it. The returned function can be used directly in `Step::finalize`.
pub fn json_formatter(
    config: JsonFormatterConfig,
) -> Result<impl Fn(&str) -> Result<Value, FlowError> + Clone + Send + Sync, FlowError> {
    if let Some(schema) = &config.schema {
        check_json_schema(schema).map_err(|error| FlowError::context("invalid formatter schema", error))?;
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
        let value = serde_json::from_str(text).map_err(|error| FlowError::context("decode JSON result", error))?;
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
