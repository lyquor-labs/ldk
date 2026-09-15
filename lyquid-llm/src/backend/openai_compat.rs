use serde_json::{Map, Value, json};

use crate::{
    FinishReason, JsonApiRequest, JsonApiResponse, LlmResult, ModelRequest, ModelResponse, PreparedJsonApiRequest,
    Usage, backend::Backend,
};
use lyquid::http;

/// OpenAI-compatible API shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiKind {
    ChatCompletions,
    Responses,
}

/// Authentication mode for OpenAI-compatible backends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    Bearer(String),
    Header { name: String, value: Vec<u8> },
}

/// Backend adapter for OpenAI-compatible Responses or Chat Completions APIs.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenAiCompatBackend {
    provider: String,
    endpoint: String,
    api_kind: ApiKind,
    auth: Option<Auth>,
    headers: Vec<http::Header>,
}

impl OpenAiCompatBackend {
    /// Create an OpenAI-compatible Responses API backend.
    pub fn responses(provider: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            endpoint: endpoint.into(),
            api_kind: ApiKind::Responses,
            auth: None,
            headers: Vec::new(),
        }
    }

    /// Create an OpenAI-compatible Chat Completions API backend.
    pub fn chat_completions(provider: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            endpoint: endpoint.into(),
            api_kind: ApiKind::ChatCompletions,
            auth: None,
            headers: Vec::new(),
        }
    }

    /// Send bearer-token auth on prepared requests.
    pub fn bearer_auth(mut self, token: &str) -> Self {
        self.auth = Some(Auth::Bearer(token.trim().to_string()));
        self
    }

    /// Add a static HTTP header to prepared requests.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push(http::Header {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Count Responses API `web_search_call` output items.
    pub fn web_search_call_count(response: &ModelResponse) -> usize {
        response
            .raw_json
            .get("output")
            .and_then(Value::as_array)
            .map_or(0, |items| {
                items
                    .iter()
                    .filter(|item| item.get("type").and_then(Value::as_str) == Some("web_search_call"))
                    .count()
            })
    }

    fn build_body(&self, request: &ModelRequest) -> Map<String, Value> {
        let mut body = match self.api_kind {
            ApiKind::ChatCompletions => self.build_chat_completions_body(request),
            ApiKind::Responses => self.build_responses_body(request),
        };
        body.extend(request.extra_body.clone());
        body
    }

    fn build_chat_completions_body(&self, request: &ModelRequest) -> Map<String, Value> {
        let mut body = Map::new();
        body.insert("model".into(), Value::String(request.model.clone()));

        let mut messages = Vec::new();
        if let Some(system) = &request.system {
            messages.push(json!({
                "role": "system",
                "content": system,
            }));
        }
        messages.push(json!({
            "role": "user",
            "content": request.prompt,
        }));
        body.insert("messages".into(), Value::Array(messages));

        if let Some(max_output_tokens) = request.max_output_tokens {
            body.insert("max_tokens".into(), json!(max_output_tokens));
        }
        if let Some(temperature) = request.temperature {
            body.insert("temperature".into(), json!(temperature));
        }

        body
    }

    fn build_responses_body(&self, request: &ModelRequest) -> Map<String, Value> {
        let mut body = Map::new();
        body.insert("model".into(), Value::String(request.model.clone()));
        body.insert("input".into(), Value::String(request.prompt.clone()));

        if let Some(system) = &request.system {
            body.insert("instructions".into(), Value::String(system.clone()));
        }
        if let Some(max_output_tokens) = request.max_output_tokens {
            body.insert("max_output_tokens".into(), json!(max_output_tokens));
        }
        if let Some(temperature) = request.temperature {
            body.insert("temperature".into(), json!(temperature));
        }

        body
    }
}

impl Backend for OpenAiCompatBackend {
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
        let mut json_request = JsonApiRequest::post(
            self.provider.clone(),
            self.endpoint.clone(),
            Value::Object(self.build_body(request)),
        )
        .expected_status(request.expected_status)
        .headers(self.headers.clone())
        .headers(request.extra_headers.clone());

        if let Some(timeout_ms) = request.timeout_ms {
            json_request = json_request.timeout_ms(timeout_ms);
        }
        if let Some(auth) = &self.auth {
            json_request = match auth {
                Auth::Bearer(token) => json_request.bearer_auth(token),
                Auth::Header { name, value } => json_request.header(name.clone(), value.clone()),
            };
        }

        json_request.into_prepared_request()
    }

    fn parse_response(&self, response: JsonApiResponse) -> LlmResult<ModelResponse> {
        let JsonApiResponse { http, json } = response;
        let text = match self.api_kind {
            ApiKind::ChatCompletions => chat_completions_text(&json),
            ApiKind::Responses => responses_text(&json),
        };
        let finish_reason = match self.api_kind {
            ApiKind::ChatCompletions => chat_completions_finish_reason(&json),
            ApiKind::Responses => responses_finish_reason(&json),
        };
        let usage = parse_usage(&json);

        Ok(ModelResponse {
            text,
            finish_reason,
            usage,
            raw_json: json,
            http,
        })
    }
}

fn first_non_empty_text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
}

fn responses_text(value: &Value) -> Option<String> {
    value.get("output_text").and_then(first_non_empty_text).or_else(|| {
        value.get("output").and_then(Value::as_array).and_then(|items| {
            items.iter().find_map(|item| {
                item.get("content").and_then(Value::as_array).and_then(|parts| {
                    parts.iter().find_map(|part| {
                        if part.get("type").and_then(Value::as_str) == Some("output_text") {
                            part.get("text").and_then(first_non_empty_text)
                        } else {
                            None
                        }
                    })
                })
            })
        })
    })
}

fn chat_completions_text(value: &Value) -> Option<String> {
    let message = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))?;

    if let Some(text) = message.get("content").and_then(first_non_empty_text) {
        return Some(text);
    }

    message.get("content").and_then(Value::as_array).and_then(|parts| {
        parts.iter().find_map(|part| {
            part.get("text")
                .and_then(first_non_empty_text)
                .or_else(|| part.get("content").and_then(first_non_empty_text))
        })
    })
}

fn parse_usage(value: &Value) -> Option<Usage> {
    let usage = value.get("usage")?;
    let input_tokens = usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))
        .and_then(Value::as_u64);
    let output_tokens = usage
        .get("output_tokens")
        .or_else(|| usage.get("completion_tokens"))
        .and_then(Value::as_u64);
    let total_tokens = usage.get("total_tokens").and_then(Value::as_u64);

    if input_tokens.is_none() && output_tokens.is_none() && total_tokens.is_none() {
        return None;
    }

    Some(Usage {
        input_tokens,
        output_tokens,
        total_tokens,
    })
}

fn chat_completions_finish_reason(value: &Value) -> Option<FinishReason> {
    value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("finish_reason"))
        .and_then(Value::as_str)
        .map(parse_finish_reason)
}

fn responses_finish_reason(value: &Value) -> Option<FinishReason> {
    if value.get("status").and_then(Value::as_str) == Some("completed") {
        return Some(FinishReason::Stop);
    }

    value
        .get("incomplete_details")
        .and_then(|details| details.get("reason"))
        .and_then(Value::as_str)
        .map(parse_finish_reason)
}

fn parse_finish_reason(reason: &str) -> FinishReason {
    match reason {
        "stop" | "completed" => FinishReason::Stop,
        "length" | "max_output_tokens" | "max_tokens" => FinishReason::Length,
        "tool_calls" => FinishReason::ToolCalls,
        "content_filter" => FinishReason::ContentFilter,
        other => FinishReason::Other(other.to_string()),
    }
}
