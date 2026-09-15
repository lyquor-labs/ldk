use serde_json::{Map, Value, json};

use crate::{
    FinishReason, JsonApiRequest, JsonApiResponse, LlmResult, ModelRequest, ModelResponse, PreparedJsonApiRequest,
    Usage, backend::Backend,
};
use lyquid::http;

/// Gemini-compatible backend adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeminiBackend {
    provider: String,
    endpoint: String,
    api_key_header_name: String,
    api_key: Option<String>,
    headers: Vec<http::Header>,
}

impl GeminiBackend {
    /// Create a Gemini-compatible backend for `endpoint`.
    pub fn new(provider: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            endpoint: endpoint.into(),
            api_key_header_name: "x-goog-api-key".into(),
            api_key: None,
            headers: Vec::new(),
        }
    }

    /// Set the API key sent on prepared requests.
    pub fn api_key(mut self, api_key: &str) -> Self {
        self.api_key = Some(api_key.trim().to_string());
        self
    }

    /// Override the API-key header name.
    pub fn api_key_header_name(mut self, name: impl Into<String>) -> Self {
        self.api_key_header_name = name.into();
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

    /// Count Google Search grounding queries in a Gemini response.
    pub fn google_search_query_count(response: &ModelResponse) -> usize {
        response
            .raw_json
            .get("candidates")
            .and_then(Value::as_array)
            .and_then(|candidates| candidates.first())
            .and_then(|candidate| candidate.get("groundingMetadata"))
            .and_then(|meta| meta.get("webSearchQueries"))
            .and_then(Value::as_array)
            .map(std::vec::Vec::len)
            .or_else(|| {
                response
                    .raw_json
                    .get("groundingMetadata")
                    .and_then(|meta| meta.get("webSearchQueries"))
                    .and_then(Value::as_array)
                    .map(std::vec::Vec::len)
            })
            .unwrap_or(0)
    }

    fn build_body(&self, request: &ModelRequest) -> Value {
        let mut body = Map::new();
        body.insert(
            "contents".into(),
            json!([{
                "role": "user",
                "parts": [{"text": request.prompt}],
            }]),
        );

        if let Some(system) = &request.system {
            body.insert(
                "system_instruction".into(),
                json!({
                    "parts": [{"text": system}],
                }),
            );
        }

        let mut generation_config = Map::new();
        if let Some(temperature) = request.temperature {
            generation_config.insert("temperature".into(), json!(temperature));
        }
        if let Some(max_output_tokens) = request.max_output_tokens {
            generation_config.insert("maxOutputTokens".into(), json!(max_output_tokens));
        }

        let mut extra_body = request.extra_body.clone();
        if let Some(Value::Object(extra_generation_config)) = extra_body.remove("generationConfig") {
            generation_config.extend(extra_generation_config);
        }
        if !generation_config.is_empty() {
            body.insert("generationConfig".into(), Value::Object(generation_config));
        }

        body.extend(extra_body);
        Value::Object(body)
    }
}

impl Backend for GeminiBackend {
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
        let mut json_request =
            JsonApiRequest::post(self.provider.clone(), self.endpoint.clone(), self.build_body(request))
                .expected_status(request.expected_status)
                .headers(self.headers.clone())
                .headers(request.extra_headers.clone());

        if let Some(timeout_ms) = request.timeout_ms {
            json_request = json_request.timeout_ms(timeout_ms);
        }
        if let Some(api_key) = &self.api_key {
            json_request = json_request.api_key_header(self.api_key_header_name.clone(), api_key);
        }

        json_request.into_prepared_request()
    }

    fn parse_response(&self, response: JsonApiResponse) -> LlmResult<ModelResponse> {
        let JsonApiResponse { http, json } = response;
        let text = gemini_text(&json);
        let finish_reason = gemini_finish_reason(&json);
        let usage = gemini_usage(&json);

        Ok(ModelResponse {
            text,
            finish_reason,
            usage,
            raw_json: json,
            http,
        })
    }
}

fn gemini_text(value: &Value) -> Option<String> {
    value
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first())
        .and_then(|candidate| candidate.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(Value::as_array)
        .and_then(|parts| {
            parts.iter().find_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                    .map(ToString::to_string)
            })
        })
}

fn gemini_finish_reason(value: &Value) -> Option<FinishReason> {
    value
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first())
        .and_then(|candidate| candidate.get("finishReason"))
        .and_then(Value::as_str)
        .map(|reason| match reason {
            "STOP" => FinishReason::Stop,
            "MAX_TOKENS" => FinishReason::Length,
            "MALFORMED_FUNCTION_CALL" => FinishReason::ToolCalls,
            "SAFETY" => FinishReason::ContentFilter,
            other => FinishReason::Other(other.to_string()),
        })
}

fn gemini_usage(value: &Value) -> Option<Usage> {
    let usage = value.get("usageMetadata")?;
    let input_tokens = usage.get("promptTokenCount").and_then(Value::as_u64);
    let output_tokens = usage.get("candidatesTokenCount").and_then(Value::as_u64);
    let total_tokens = usage.get("totalTokenCount").and_then(Value::as_u64);

    if input_tokens.is_none() && output_tokens.is_none() && total_tokens.is_none() {
        return None;
    }

    Some(Usage {
        input_tokens,
        output_tokens,
        total_tokens,
    })
}
