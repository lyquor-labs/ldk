use serde_json::{Map, Value, json};

use crate::{
    FinishReason, JsonApiRequest, JsonApiResponse, LlmError, LlmResult, ModelRequest, ModelResponse, OutputFormat,
    PreparedJsonApiRequest, Usage,
    backend::{Backend, required_api_key},
};
use lyquid::http;

/// Gemini-compatible backend adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeminiBackend {
    provider: String,
    endpoint: Endpoint,
    api_key_header_name: String,
    api_key: Option<String>,
    headers: Vec<http::Header>,
    output_format: Option<OutputFormat>,
    web_search: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Endpoint {
    Fixed(String),
    GoogleAi,
}

impl GeminiBackend {
    /// Use Google's Gemini generateContent endpoint with API-key authentication.
    /// Each request selects its model with [`ModelRequest::model`] (for example, `gemini-2.5-flash`).
    pub fn google_ai(api_key: &str) -> LlmResult<Self> {
        Ok(Self {
            endpoint: Endpoint::GoogleAi,
            ..Self::new("gemini", "").api_key(required_api_key("gemini", api_key)?)
        })
    }

    /// Create a Gemini-compatible backend for `endpoint`.
    pub fn new(provider: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            endpoint: Endpoint::Fixed(endpoint.into()),
            api_key_header_name: "x-goog-api-key".into(),
            api_key: None,
            headers: Vec::new(),
            output_format: None,
            web_search: false,
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

    /// Set the output format for requests made through this backend.
    /// Raw `generationConfig` fields override corresponding generated fields.
    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = Some(format);
        self
    }

    /// Enable Google Search grounding. The model decides whether to search.
    /// Choose a model-supported output format; this does not change the configured format.
    /// Raw request `tools` override the generated tool declaration.
    pub fn web_search(mut self) -> Self {
        self.web_search = true;
        self
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
        if let Some(format) = &self.output_format {
            generation_config.insert(
                "responseMimeType".into(),
                json!(match format {
                    OutputFormat::Text => "text/plain",
                    OutputFormat::Json | OutputFormat::JsonSchema { .. } => "application/json",
                }),
            );
            if let OutputFormat::JsonSchema { schema, .. } = format {
                generation_config.insert("responseJsonSchema".into(), schema.clone());
            }
        }

        let mut extra_body = request.extra_body.clone();
        if let Some(Value::Object(extra_generation_config)) = extra_body.remove("generationConfig") {
            generation_config.extend(extra_generation_config);
        }
        if !generation_config.is_empty() {
            body.insert("generationConfig".into(), Value::Object(generation_config));
        }

        if self.web_search {
            body.insert("tools".into(), json!([{"google_search": {}}]));
        }
        body.extend(extra_body);
        Value::Object(body)
    }
}

impl Backend for GeminiBackend {
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
        let endpoint = match &self.endpoint {
            Endpoint::Fixed(endpoint) => endpoint.clone(),
            Endpoint::GoogleAi => {
                let model = request.model.trim();
                if model.is_empty() {
                    return Err(LlmError::Backend {
                        provider: self.provider.clone(),
                        message: "the model must not be empty".into(),
                    });
                }
                format!("https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent")
            }
        };
        let mut json_request = JsonApiRequest::post(self.provider.clone(), endpoint, self.build_body(request))
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
        let web_search_used = grounding_items(&json, "webSearchQueries").is_some_and(|queries| !queries.is_empty());
        let sources = grounding_items(&json, "groundingChunks")
            .into_iter()
            .flatten()
            .filter_map(|chunk| chunk.pointer("/web/uri")?.as_str())
            .map(str::to_owned)
            .collect();

        Ok(ModelResponse {
            text,
            finish_reason,
            usage,
            web_search_used,
            sources,
            raw_json: json,
            http,
        })
    }
}

fn grounding_items<'a>(value: &'a Value, field: &str) -> Option<&'a Vec<Value>> {
    value
        .pointer("/candidates/0/groundingMetadata")
        .and_then(|metadata| metadata.get(field))
        .and_then(Value::as_array)
        .or_else(|| value.get("groundingMetadata")?.get(field)?.as_array())
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

#[cfg(test)]
mod tests {
    use lyquid_test::test;
    use serde_json::json;

    use super::*;

    fn body(backend: &dyn Backend, request: &ModelRequest) -> Value {
        serde_json::from_slice(&backend.prepare_request(request).unwrap().request.body.unwrap()).unwrap()
    }

    fn header<'a>(prepared: &'a PreparedJsonApiRequest, name: &str) -> &'a [u8] {
        &prepared
            .request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .unwrap()
            .value
    }

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": false
        })
    }

    #[test]
    fn api_key() {
        assert!(GeminiBackend::google_ai(" \n").is_err());
        let prepared = GeminiBackend::google_ai(" fixture-key ")
            .unwrap()
            .prepare_request(&ModelRequest::new("chosen-model", "prompt"))
            .unwrap();
        assert_eq!(header(&prepared, "x-goog-api-key"), b"fixture-key");
    }

    #[test]
    fn output_formats() {
        let request = ModelRequest::new("chosen-model", "Return JSON");
        for (format, mime) in [
            (OutputFormat::Json, "application/json"),
            (OutputFormat::Text, "text/plain"),
        ] {
            let backend = GeminiBackend::google_ai("fixture-key")
                .unwrap()
                .output_format(OutputFormat::json_schema("answer", schema()))
                .output_format(format);
            assert_eq!(
                body(&backend, &request)["generationConfig"],
                json!({"responseMimeType": mime})
            );
        }
        assert!(
            body(&GeminiBackend::google_ai("fixture-key").unwrap(), &request)
                .get("generationConfig")
                .is_none()
        );
    }

    #[test]
    fn request_options() {
        let backend = GeminiBackend::google_ai("fixture-key")
            .unwrap()
            .output_format(OutputFormat::json_schema("answer", schema()));
        for model in ["gemini-2.5-flash", "gemini-2.5-pro"] {
            let request = ModelRequest::new(model, "Return JSON")
                .max_output_tokens(8192)
                .temperature(0.0)
                .timeout_ms(120_000);
            let prepared = backend.prepare_request(&request).unwrap();
            assert_eq!(
                prepared.request.url,
                format!("https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent")
            );
            assert_eq!(prepared.options.unwrap().timeout_ms, Some(120_000));
            assert_eq!(
                body(&backend, &request)["generationConfig"],
                json!({
                    "maxOutputTokens": 8192, "temperature": 0.0,
                    "responseMimeType": "application/json", "responseJsonSchema": schema()
                })
            );
        }
        assert!(backend.prepare_request(&ModelRequest::new(" ", "prompt")).is_err());
    }

    #[test]
    fn custom_endpoint() {
        let backend = GeminiBackend::new("custom", "https://model.example/generate")
            .api_key_header_name("x-custom-key")
            .api_key("fixture-key")
            .output_format(OutputFormat::Json);
        let request = ModelRequest::new("ignored-for-fixed-endpoint", "prompt")
            .max_output_tokens(8192)
            .body_field(
                "generationConfig",
                json!({"responseMimeType": "text/plain", "temperature": 0.5}),
            );
        let prepared = backend.prepare_request(&request).unwrap();
        assert_eq!(prepared.request.url, "https://model.example/generate");
        assert_eq!(header(&prepared, "x-custom-key"), b"fixture-key");
        assert_eq!(
            body(&backend, &request)["generationConfig"],
            json!({
                "maxOutputTokens": 8192, "responseMimeType": "text/plain", "temperature": 0.5
            })
        );
    }

    #[test]
    fn web_search_options() {
        let request = ModelRequest::new("gemini-2.5-flash", "Search for an answer")
            .temperature(0.0)
            .max_output_tokens(8192);
        let backend = GeminiBackend::google_ai("fixture-key").unwrap();
        assert!(body(&backend, &request).get("tools").is_none());
        let backend = backend.output_format(OutputFormat::Text).web_search();
        let output = body(&backend, &request);
        assert_eq!(output["tools"], json!([{"google_search": {}}]));
        assert_eq!(
            output["generationConfig"],
            json!({
                "temperature": 0.0, "maxOutputTokens": 8192, "responseMimeType": "text/plain"
            })
        );
        assert_eq!(
            body(&backend, &request.body_field("tools", json!([])))["tools"],
            json!([])
        );
    }

    #[test]
    fn search_metadata() {
        let backend = GeminiBackend::google_ai("fixture-key").unwrap();
        let parse = |json| {
            backend
                .parse_response(JsonApiResponse {
                    http: http::Response {
                        status: 200,
                        headers: vec![],
                        body: vec![],
                    },
                    json,
                })
                .unwrap()
        };
        let grounding = json!({
            "webSearchQueries": ["query"],
            "groundingChunks": [{"web": {"uri": " https://example.com "}}, {}, {"web": {"uri": 1}},
                {"web": {"uri": "https://example.com"}}, {"web": {"uri": "https://example.com"}}]
        });
        for raw in [
            json!({"candidates": [{
                "content": {"parts": [{"text": "answer"}]}, "groundingMetadata": grounding
            }]}),
            json!({"candidates": [{"content": {"parts": [{"text": "answer"}]}}], "groundingMetadata": grounding}),
        ] {
            let response = parse(raw.clone());
            assert!(response.web_search_used);
            assert_eq!(response.text.as_deref(), Some("answer"));
            assert_eq!(
                response.sources,
                [" https://example.com ", "https://example.com", "https://example.com"]
            );
            assert_eq!(response.raw_json, raw);
        }
        for raw in [
            json!({}),
            json!({"candidates": []}),
            json!({"groundingMetadata": "malformed"}),
            json!({"groundingMetadata": {"webSearchQueries": [], "groundingChunks": []}}),
        ] {
            let response = parse(raw);
            assert!(!response.web_search_used);
            assert!(response.sources.is_empty());
        }
        let response =
            parse(json!({"groundingMetadata": {"groundingChunks": [{"web": {"uri": "https://example.com"}}]}}));
        assert!(!response.web_search_used);
        assert_eq!(response.sources, ["https://example.com"]);
        let response = parse(json!({"groundingMetadata": {"webSearchQueries": ["query"]}}));
        assert!(response.web_search_used);
        assert!(response.sources.is_empty());
    }
}
