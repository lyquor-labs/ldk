use serde_json::{Map, Value, json};

use crate::{
    FinishReason, JsonApiRequest, JsonApiResponse, LlmError, LlmResult, ModelRequest, ModelResponse, OutputFormat,
    PreparedJsonApiRequest, Usage,
    backend::{Backend, required_api_key},
};
use lyquid::http;

/// OpenAI reasoning budget hint. Availability depends on the selected model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    XHigh,
    Max,
}

impl ReasoningEffort {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
            Self::Max => "max",
        }
    }
}

/// OpenAI output verbosity hint. Availability depends on the selected model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verbosity {
    Low,
    Medium,
    High,
}

impl Verbosity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

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

/// Web-search options for the Responses API. Defaults allow the model to choose when to search.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WebSearchOptions {
    /// Require a tool call. Applications can also check [`ModelResponse::web_search_used`].
    pub required: bool,
    /// Maximum built-in tool calls in one response.
    pub max_tool_calls: Option<u8>,
    /// Optional domain filter. When present, the list is sent as provided, including an empty list.
    pub allowed_domains: Option<Vec<String>>,
}

/// Backend adapter for OpenAI-compatible Responses or Chat Completions APIs.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenAiCompatBackend {
    provider: String,
    endpoint: String,
    api_kind: ApiKind,
    auth: Option<Auth>,
    headers: Vec<http::Header>,
    output_format: Option<OutputFormat>,
    reasoning_effort: Option<ReasoningEffort>,
    verbosity: Option<Verbosity>,
    web_search: Option<WebSearchOptions>,
}

impl OpenAiCompatBackend {
    /// Use OpenAI's Responses endpoint with bearer authentication.
    /// Rejects an empty key locally; model choice remains on [`ModelRequest`].
    pub fn openai(api_key: &str) -> LlmResult<Self> {
        Ok(Self::responses("openai", "https://api.openai.com/v1/responses")
            .bearer_auth(required_api_key("openai", api_key)?))
    }

    /// Create an OpenAI-compatible Responses API backend.
    pub fn responses(provider: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            endpoint: endpoint.into(),
            api_kind: ApiKind::Responses,
            auth: None,
            headers: Vec::new(),
            output_format: None,
            reasoning_effort: None,
            verbosity: None,
            web_search: None,
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
            output_format: None,
            reasoning_effort: None,
            verbosity: None,
            web_search: None,
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

    /// Set the output format for requests made through this backend.
    /// Raw request body fields override the generated fields at the top level.
    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = Some(format);
        self
    }

    /// Set a model-supported reasoning effort without spelling provider JSON fields.
    pub fn reasoning_effort(mut self, effort: ReasoningEffort) -> Self {
        self.reasoning_effort = Some(effort);
        self
    }

    /// Set a model-supported output verbosity.
    pub fn verbosity(mut self, verbosity: Verbosity) -> Self {
        self.verbosity = Some(verbosity);
        self
    }

    /// Enable Responses web search and request its source URLs.
    /// Raw request fields can override the generated tools and search options.
    /// Preparing a Chat Completions request with this option returns an error.
    pub fn web_search(mut self, options: WebSearchOptions) -> Self {
        self.web_search = Some(options);
        self
    }

    fn build_body(&self, request: &ModelRequest) -> Map<String, Value> {
        let mut body = match self.api_kind {
            ApiKind::ChatCompletions => self.build_chat_completions_body(request),
            ApiKind::Responses => self.build_responses_body(request),
        };
        self.apply_options(&mut body);
        body.extend(request.extra_body.clone());
        body
    }

    fn apply_options(&self, body: &mut Map<String, Value>) {
        if let Some(search) = &self.web_search {
            let mut tool = json!({"type": "web_search"});
            if let Some(domains) = &search.allowed_domains {
                tool["filters"] = json!({"allowed_domains": domains});
            }
            body.insert("tools".into(), json!([tool]));
            body.insert(
                "tool_choice".into(),
                json!(if search.required { "required" } else { "auto" }),
            );
            body.insert("include".into(), json!(["web_search_call.action.sources"]));
            if let Some(limit) = search.max_tool_calls {
                body.insert("max_tool_calls".into(), json!(limit));
            }
        }
        let format = self.output_format.as_ref().map(|format| match format {
            OutputFormat::Text => json!({"type": "text"}),
            OutputFormat::Json => json!({"type": "json_object"}),
            OutputFormat::JsonSchema { name, schema } => match self.api_kind {
                ApiKind::Responses => json!({"type": "json_schema", "name": name, "strict": true, "schema": schema}),
                ApiKind::ChatCompletions => json!({"type": "json_schema", "json_schema": {
                    "name": name, "strict": true, "schema": schema
                }}),
            },
        });
        match self.api_kind {
            ApiKind::Responses => {
                let mut text = Map::new();
                if let Some(format) = format {
                    text.insert("format".into(), format);
                }
                if let Some(verbosity) = self.verbosity {
                    text.insert("verbosity".into(), json!(verbosity.as_str()));
                }
                if !text.is_empty() {
                    body.insert("text".into(), Value::Object(text));
                }
                if let Some(effort) = self.reasoning_effort {
                    body.insert("reasoning".into(), json!({"effort": effort.as_str()}));
                }
            }
            ApiKind::ChatCompletions => {
                if let Some(format) = format {
                    body.insert("response_format".into(), format);
                }
                if let Some(verbosity) = self.verbosity {
                    body.insert("verbosity".into(), json!(verbosity.as_str()));
                }
                if let Some(effort) = self.reasoning_effort {
                    body.insert("reasoning_effort".into(), json!(effort.as_str()));
                }
            }
        }
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
        if self.web_search.is_some() && self.api_kind == ApiKind::ChatCompletions {
            return Err(LlmError::Backend {
                provider: self.provider.clone(),
                message: "web search requires the Responses API".into(),
            });
        }
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
        let (web_search_used, sources) = match self.api_kind {
            ApiKind::Responses => responses_web_search(&json),
            ApiKind::ChatCompletions => (false, Vec::new()),
        };

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

fn responses_web_search(value: &Value) -> (bool, Vec<String>) {
    let mut used = false;
    let mut sources = Vec::new();
    for item in value.get("output").and_then(Value::as_array).into_iter().flatten() {
        if item.get("type").and_then(Value::as_str) != Some("web_search_call") {
            continue;
        }
        used = true;
        if let Some(items) = item.pointer("/action/sources").and_then(Value::as_array) {
            sources.extend(
                items
                    .iter()
                    .filter_map(|source| source.get("url")?.as_str())
                    .map(str::to_owned),
            );
        }
    }
    (used, sources)
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
        assert!(OpenAiCompatBackend::openai(" \n").is_err());
        let prepared = OpenAiCompatBackend::openai(" fixture-key ")
            .unwrap()
            .prepare_request(&ModelRequest::new("chosen-model", "prompt"))
            .unwrap();
        assert_eq!(prepared.request.url, "https://api.openai.com/v1/responses");
        assert_eq!(header(&prepared, "authorization"), b"Bearer fixture-key");
    }

    #[test]
    fn responses_options() {
        let backend = OpenAiCompatBackend::openai("fixture-key").unwrap();
        let format = OutputFormat::json_schema("answer", schema());
        let first = backend.clone().output_format(format.clone()).verbosity(Verbosity::Low);
        let second = backend
            .output_format(OutputFormat::Text)
            .verbosity(Verbosity::Low)
            .output_format(format);
        let request = ModelRequest::new("gpt-5.4", "Return JSON")
            .system("Answer the question")
            .max_output_tokens(8192)
            .body_field("tools", json!([{"type": "web_search"}]));
        assert_eq!(body(&first, &request), body(&second, &request));
        assert_eq!(
            body(&first.reasoning_effort(ReasoningEffort::None), &request),
            json!({
                "model": "gpt-5.4", "input": "Return JSON", "instructions": "Answer the question",
                "max_output_tokens": 8192, "tools": [{"type": "web_search"}],
                "reasoning": {"effort": "none"},
                "text": {"verbosity": "low", "format": {
                    "type": "json_schema", "name": "answer", "strict": true, "schema": schema()
                }}
            })
        );
    }

    #[test]
    fn chat_options() {
        let backend = OpenAiCompatBackend::chat_completions("custom", "https://model.example/chat")
            .output_format(OutputFormat::json_schema("answer", schema()))
            .reasoning_effort(ReasoningEffort::Low)
            .verbosity(Verbosity::High);
        let body = body(&backend, &ModelRequest::new("chosen-model", "Return JSON"));
        assert_eq!(
            body["response_format"],
            json!({"type": "json_schema", "json_schema": {
                "name": "answer", "strict": true, "schema": schema()
            }})
        );
        assert_eq!(body["reasoning_effort"], "low");
        assert_eq!(body["verbosity"], "high");
        assert!(body.get("text").is_none());
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn output_formats() {
        let request = ModelRequest::new("chosen-model", "Return JSON");
        for (format, kind) in [(OutputFormat::Json, "json_object"), (OutputFormat::Text, "text")] {
            let responses = OpenAiCompatBackend::openai("fixture-key")
                .unwrap()
                .output_format(format.clone());
            assert_eq!(body(&responses, &request)["text"]["format"], json!({"type": kind}));
            let chat =
                OpenAiCompatBackend::chat_completions("custom", "https://model.example/chat").output_format(format);
            assert_eq!(body(&chat, &request)["response_format"], json!({"type": kind}));
        }
        assert!(
            body(&OpenAiCompatBackend::openai("fixture-key").unwrap(), &request)
                .get("text")
                .is_none()
        );
    }

    #[test]
    fn custom_endpoint() {
        let request = ModelRequest::new("chosen-model", "prompt")
            .body_field("text", json!({"format": {"type": "text"}}))
            .body_field("reasoning", json!({"effort": "custom-effort"}));
        let backend = OpenAiCompatBackend::responses("custom", "https://model.example/responses")
            .output_format(OutputFormat::Json)
            .verbosity(Verbosity::Low)
            .reasoning_effort(ReasoningEffort::High);
        assert_eq!(
            backend.prepare_request(&request).unwrap().request.url,
            "https://model.example/responses"
        );
        let output = body(&backend, &request);
        assert_eq!(output["text"], request.extra_body["text"]);
        assert_eq!(output["reasoning"], request.extra_body["reasoning"]);
    }

    #[test]
    fn web_search_options() {
        let request = ModelRequest::new("gpt-5.4", "Search for an answer");
        let backend = OpenAiCompatBackend::openai("fixture-key").unwrap();
        assert!(body(&backend, &request).get("tools").is_none());
        let automatic = body(&backend.clone().web_search(WebSearchOptions::default()), &request);
        assert_eq!(automatic["tool_choice"], "auto");
        assert!(automatic["tools"][0].get("filters").is_none());
        assert!(automatic.get("max_tool_calls").is_none());
        let filtered = backend.clone().web_search(WebSearchOptions {
            allowed_domains: Some(Vec::new()),
            ..WebSearchOptions::default()
        });
        assert_eq!(
            body(&filtered, &request)["tools"][0]["filters"]["allowed_domains"],
            json!([])
        );

        let backend = backend.web_search(WebSearchOptions {
            required: true,
            max_tool_calls: Some(6),
            allowed_domains: Some(vec!["example.com".into()]),
        });
        let output = body(&backend, &request);
        assert_eq!(
            output["tools"],
            json!([{"type": "web_search", "filters": {"allowed_domains": ["example.com"]}}])
        );
        assert_eq!(output["tool_choice"], "required");
        assert_eq!(output["max_tool_calls"], 6);
        assert_eq!(output["include"], json!(["web_search_call.action.sources"]));
        let request = request
            .body_field("tools", json!([]))
            .body_field("tool_choice", json!("none"))
            .body_field("include", json!([]))
            .body_field("max_tool_calls", json!(2));
        let output = body(&backend, &request);
        for (field, value) in &request.extra_body {
            assert_eq!(&output[field], value);
        }
    }

    #[test]
    fn chat_search_rejected() {
        let backend = OpenAiCompatBackend::chat_completions("custom", "https://model.example/chat")
            .web_search(WebSearchOptions::default());
        assert!(
            backend
                .prepare_request(&ModelRequest::new("model", "prompt"))
                .unwrap_err()
                .to_string()
                .contains("Responses API")
        );
    }

    #[test]
    fn search_metadata() {
        let backend = OpenAiCompatBackend::openai("fixture-key").unwrap();
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
        let raw = json!({"output_text": "answer", "output": [
            {"type": "message", "action": {"sources": [{"url": "ignore-message"}]}},
            {"type": "web_search_call", "action": {"sources": [
                {"url": " https://example.com "}, {}, {"url": 7}
            ]}},
            {"type": "web_search_call", "action": {"sources": [
                {"url": "https://example.com"}, {"url": "https://example.com"}, {"url": "http://example.org"}
            ]}}
        ]});
        let response = parse(raw.clone());
        assert!(response.web_search_used);
        assert_eq!(response.text.as_deref(), Some("answer"));
        assert_eq!(
            response.sources,
            [
                " https://example.com ",
                "https://example.com",
                "https://example.com",
                "http://example.org"
            ]
        );
        assert_eq!(response.raw_json, raw);
        for json in [
            json!({}),
            json!({"output": []}),
            json!({"output": "malformed"}),
            json!({"output": [{"type": "message", "action": {"sources": [{"url": "https://example.com"}]}}]}),
        ] {
            let response = parse(json);
            assert!(!response.web_search_used);
            assert!(response.sources.is_empty());
        }
        let response = parse(json!({"output": [{"type": "web_search_call"}]}));
        assert!(response.web_search_used);
        assert!(response.sources.is_empty());
    }
}
