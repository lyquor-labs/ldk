#![doc(html_no_source)] // remove it upon open-source

//! Provider-neutral LLM request and response adapters for Lyquid instance functions.
//! With the `ldk` feature, `call_model` sends requests through `lyquor_api::http_request`.
//!
//! [`backend::openai_compat::OpenAiCompatBackend::openai`] and
//! [`backend::gemini::GeminiBackend::google_ai`] provide default endpoints and authentication.
//! Configure [`OutputFormat`] on a backend to request text, JSON mode, or schema-constrained JSON.
//! [`ModelRequest`] carries each call's input and request options.
//! [`ModelConfig`] combines a model and backend with shared request defaults. Configure a built-in
//! model with [`ModelConfig::openai`] or [`ModelConfig::gemini`], then call [`ModelBuilder::build`].
//! Accumulate reported [`Usage`] across attempted calls with [`UsageTotals`].
//! With `ldk`, `UsageTracker` shares application-defined accounting state across call sites.
//! Attach [`with_usage_observer`] to a backend to observe its model-call attempts automatically.

#[cfg(feature = "ldk")] use std::sync::Arc;

use lyquid::http;
#[cfg(feature = "ldk")] use lyquid::prelude::Mutex;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::capture_status_body;

/// Provider-specific request and response adapters.
pub mod backend;

mod error;
mod model;

pub use backend::Backend;
pub use error::{LlmError, LlmResult};
pub use model::{ModelBuilder, ModelConfig};

const APPLICATION_JSON: &[u8] = b"application/json";

/// Output format requested from a provider. Model support and supported JSON Schema keywords
/// depend on the provider; these options do not perform local response validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain text, without a JSON output constraint.
    Text,
    /// JSON mode, without a schema constraint. The prompt must still request JSON.
    Json,
    /// Schema-constrained JSON. OpenAI uses strict mode; Gemini uses its JSON Schema format.
    JsonSchema { name: String, schema: Value },
}

impl OutputFormat {
    /// The name identifies the schema to OpenAI; Gemini only sends the schema itself.
    pub fn json_schema(name: impl Into<String>, schema: Value) -> Self {
        Self::JsonSchema {
            name: name.into(),
            schema,
        }
    }
}

/// Provider-specific JSON HTTP request builder.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonApiRequest {
    provider: String,
    url: String,
    headers: Vec<http::Header>,
    body: Value,
    timeout_ms: Option<u64>,
    expected_status: u16,
}

/// Provider-specific JSON HTTP response with parsed body.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonApiResponse {
    pub http: http::Response,
    pub json: Value,
}

/// HTTP request plus expected response status prepared by a backend.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedJsonApiRequest {
    pub provider: String,
    pub expected_status: u16,
    pub request: http::Request,
    pub options: Option<http::RequestOptions>,
}

/// Provider-neutral model request.
#[derive(Clone, Debug, PartialEq)]
pub struct ModelRequest {
    pub model: String,
    pub system: Option<String>,
    pub prompt: String,
    pub timeout_ms: Option<u64>,
    pub max_output_tokens: Option<u16>,
    pub temperature: Option<f32>,
    pub expected_status: u16,
    pub extra_headers: Vec<http::Header>,
    pub extra_body: Map<String, Value>,
}

/// Token usage reported by a model provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

impl Usage {
    /// Accumulates another call's reported tokens. Missing fields or overflowing sums remain unknown.
    /// Provider totals are accumulated independently of input and output counts.
    pub fn accumulate(&mut self, usage: Option<&Self>) {
        self.input_tokens = add_token_counts(self.input_tokens, usage.and_then(|usage| usage.input_tokens));
        self.output_tokens = add_token_counts(self.output_tokens, usage.and_then(|usage| usage.output_tokens));
        self.total_tokens = add_token_counts(self.total_tokens, usage.and_then(|usage| usage.total_tokens));
    }
}

/// Cumulative provider-reported token usage across attempted model calls.
///
/// Starts with zero attempts and known zero token counts. A missing token field or an overflowing
/// sum makes that cumulative field `None`, including after subsequent calls. Total tokens are
/// accumulated directly from the provider; they are never inferred from input and output tokens.
/// The caller owns these counters and explicitly records each attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageTotals {
    /// Attempted calls, including failures without usage; not a count of confirmed billable requests.
    pub call_attempts: u64,
    /// Accumulated token counts, serialized alongside `call_attempts`.
    #[serde(flatten)]
    pub usage: Usage,
}

impl Default for UsageTotals {
    fn default() -> Self {
        Self {
            call_attempts: 0,
            usage: Usage {
                input_tokens: Some(0),
                output_tokens: Some(0),
                total_tokens: Some(0),
            },
        }
    }
}

impl UsageTotals {
    /// Records one attempted call. Pass `None` when the call fails without usage or usage is omitted.
    pub fn record(&mut self, usage: Option<&Usage>) {
        self.call_attempts += 1;
        self.usage.accumulate(usage);
    }

    /// Combines two disjoint groups of attempts without changing either source.
    /// A token field remains unknown if it is unknown in either group.
    pub fn combined(&self, other: &Self) -> Self {
        let mut combined = self.clone();
        combined.call_attempts += other.call_attempts;
        combined.usage.accumulate(Some(&other.usage));
        combined
    }
}

/// Shared accounting state for model calls, available with the `ldk` feature.
///
/// The application defines its state, categories, and recording operation. Clones share one
/// ledger; snapshots clone its value. Keep the tracker outside restorable Flow State so restoring
/// application history does not refund usage, and capture clones in model-call observers instead.
#[cfg(feature = "ldk")]
pub struct UsageTracker<S>(Arc<Mutex<S>>);

#[cfg(feature = "ldk")]
impl<S> Clone for UsageTracker<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(feature = "ldk")]
impl<S: Default> Default for UsageTracker<S> {
    fn default() -> Self {
        Self::new(S::default())
    }
}

#[cfg(feature = "ldk")]
impl<S> UsageTracker<S> {
    /// Creates a new, independent ledger with application-defined initial state.
    pub fn new(state: S) -> Self {
        Self(Arc::new(Mutex::new(state)))
    }
}

#[cfg(feature = "ldk")]
impl<S: Clone> UsageTracker<S> {
    /// Applies a recording operation and clones the resulting state under the same lock.
    ///
    /// Only the supplied operation changes counters: initializing session metadata does not
    /// itself count as a model-call attempt. The operation must be short and synchronous; do not
    /// call the same tracker, a model, or logging code from it. Use the returned snapshot after
    /// the lock is released to render or log usage.
    pub fn record(&self, record: impl FnOnce(&mut S)) -> S {
        let mut state = self.0.lock();
        record(&mut state);
        state.clone()
    }

    /// Clones the current state without changing counters.
    pub fn snapshot(&self) -> S {
        self.0.lock().clone()
    }
}

/// Attaches an observer to a backend without changing its requests or responses.
///
/// With the `ldk` feature, `call_model` invokes the observer once per attempt before returning,
/// including failures before a response is available. `None` means failure or omitted usage.
/// Preparing requests or parsing responses directly does not notify the observer.
///
/// The wrapped backend receives the notification first, so nested observers each run once.
/// Register each accounting operation at one layer to avoid counting the same attempt twice.
pub fn with_usage_observer<B: Backend>(backend: B, observer: impl Fn(Option<&Usage>)) -> impl Backend {
    ObservedBackend { backend, observer }
}

struct ObservedBackend<B, F> {
    backend: B,
    observer: F,
}

impl<B: Backend, F: Fn(Option<&Usage>)> Backend for ObservedBackend<B, F> {
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
        self.backend.prepare_request(request)
    }

    fn parse_response(&self, response: JsonApiResponse) -> LlmResult<ModelResponse> {
        self.backend.parse_response(response)
    }

    fn on_usage(&self, usage: Option<&Usage>) {
        self.backend.on_usage(usage);
        (self.observer)(usage);
    }
}

fn add_token_counts(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    left.zip(right).and_then(|(left, right)| left.checked_add(right))
}

/// Provider-neutral model finish reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
    Other(String),
}

/// Provider-neutral model response.
#[derive(Clone, Debug, PartialEq)]
pub struct ModelResponse {
    pub text: Option<String>,
    pub finish_reason: Option<FinishReason>,
    pub usage: Option<Usage>,
    /// Whether the response contains provider-reported web-search calls or queries.
    /// This does not guarantee that the answer is supported by the returned sources.
    pub web_search_used: bool,
    /// Source URLs reported by web search, before application filtering or deduplication.
    pub sources: Vec<String>,
    pub raw_json: Value,
    pub http: http::Response,
}

impl JsonApiRequest {
    /// Create a POST request with JSON content type.
    pub fn post(provider: impl Into<String>, url: impl Into<String>, body: Value) -> Self {
        Self {
            provider: provider.into(),
            url: url.into(),
            headers: vec![http::Header {
                name: "Content-Type".into(),
                value: APPLICATION_JSON.to_vec(),
            }],
            body,
            timeout_ms: None,
            expected_status: 200,
        }
    }

    /// Set the HTTP timeout in milliseconds.
    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Set the expected HTTP status code.
    pub fn expected_status(mut self, status: u16) -> Self {
        self.expected_status = status;
        self
    }

    /// Add an HTTP header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push(http::Header {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Add multiple HTTP headers.
    pub fn headers(mut self, headers: impl IntoIterator<Item = http::Header>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Add an `Authorization: Bearer ...` header.
    pub fn bearer_auth(self, token: &str) -> Self {
        self.header("Authorization", format!("Bearer {}", token.trim()))
    }

    /// Add an API key header.
    pub fn api_key_header(self, name: impl Into<String>, api_key: &str) -> Self {
        self.header(name, api_key.trim().as_bytes().to_vec())
    }

    /// Convert this builder into a Lyquid HTTP request.
    pub fn into_http_request(self) -> LlmResult<http::Request> {
        let body = serde_json::to_vec(&self.body).map_err(|source| LlmError::RequestEncode {
            provider: self.provider.clone(),
            source,
        })?;

        Ok(http::Request {
            method: http::Method::Post,
            url: self.url,
            headers: self.headers,
            body: Some(body),
        })
    }

    /// Convert this builder into a prepared request with options and status expectation.
    pub fn into_prepared_request(self) -> LlmResult<PreparedJsonApiRequest> {
        let provider = self.provider.clone();
        let expected_status = self.expected_status;
        let options = self.timeout_ms.map(|timeout_ms| http::RequestOptions {
            timeout_ms: Some(timeout_ms),
        });
        let request = self.into_http_request()?;

        Ok(PreparedJsonApiRequest {
            provider,
            expected_status,
            request,
            options,
        })
    }
}

impl JsonApiResponse {
    /// Parse a Lyquid HTTP response as JSON after checking the expected status code.
    pub fn from_http(provider: impl Into<String>, expected_status: u16, response: http::Response) -> LlmResult<Self> {
        let provider = provider.into();
        if response.status != expected_status {
            // Capture the body before returning — for non-2xx LLM responses, the meaningful
            // diagnostic (rate-limit reason, malformed-request hint, model-unavailable message)
            // lives in the body, not the status line. Truncated to UNEXPECTED_STATUS_BODY_CAP
            // so an HTML 502 page doesn't blow up logs.
            return Err(LlmError::UnexpectedStatus {
                provider,
                status: response.status,
                body: capture_status_body(&response.body),
            });
        }

        let json = serde_json::from_slice(&response.body).map_err(|source| LlmError::ResponseDecode {
            provider,
            // Same rationale as UnexpectedStatus above: on a 200 + malformed-JSON response the body
            // is the only diagnostic. Captured lazily here so the success path allocates nothing.
            body: capture_status_body(&response.body),
            source,
        })?;

        Ok(Self { http: response, json })
    }
}

impl ModelRequest {
    /// Create a provider-neutral model request with a user prompt.
    pub fn new(model: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            system: None,
            prompt: prompt.into(),
            timeout_ms: None,
            max_output_tokens: None,
            temperature: None,
            expected_status: 200,
            extra_headers: Vec::new(),
            extra_body: Map::new(),
        }
    }

    /// Set system instructions.
    pub fn system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Set the HTTP timeout in milliseconds.
    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Set the provider max output token hint.
    pub fn max_output_tokens(mut self, max_output_tokens: u16) -> Self {
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    /// Set the provider temperature hint.
    pub fn temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set the expected HTTP status code.
    pub fn expected_status(mut self, expected_status: u16) -> Self {
        self.expected_status = expected_status;
        self
    }

    /// Add an extra provider HTTP header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.extra_headers.push(http::Header {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Add one extra provider-specific JSON body field.
    pub fn body_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra_body.insert(key.into(), value);
        self
    }

    /// Add multiple provider-specific JSON body fields.
    pub fn body_fields(mut self, fields: impl IntoIterator<Item = (String, Value)>) -> Self {
        self.extra_body.extend(fields);
        self
    }
}

/// Call a model from a Lyquid WASM guest using the backend's prepared HTTP request.
/// Reports usage once through [`Backend::on_usage`] before returning the response or error.
#[cfg(feature = "ldk")]
pub fn call_model<B: Backend + ?Sized>(backend: &B, request: &ModelRequest) -> LlmResult<ModelResponse> {
    let result = (|| {
        let prepared = backend.prepare_request(request)?;
        let response =
            lyquid::runtime::lyquor_api::http_request(prepared.request, prepared.options).map_err(|source| {
                LlmError::Transport {
                    provider: prepared.provider.clone(),
                    source,
                }
            })?;
        let response = JsonApiResponse::from_http(prepared.provider, prepared.expected_status, response)?;
        backend.parse_response(response)
    })();
    backend.on_usage(result.as_ref().ok().and_then(|response| response.usage.as_ref()));
    result
}

#[cfg(test)]
mod tests {
    use lyquid_test::test;

    use super::*;

    #[test]
    fn usage_totals() {
        let mut totals = UsageTotals::default();
        assert_eq!(
            totals,
            UsageTotals {
                call_attempts: 0,
                usage: Usage {
                    input_tokens: Some(0),
                    output_tokens: Some(0),
                    total_tokens: Some(0),
                },
            }
        );
        let usage = Usage {
            input_tokens: Some(20),
            output_tokens: Some(10),
            total_tokens: Some(35),
        };
        totals.record(Some(&usage));
        totals.record(Some(&usage));
        let mut other = UsageTotals::default();
        other.record(Some(&Usage {
            input_tokens: Some(5),
            output_tokens: Some(3),
            total_tokens: Some(9),
        }));
        assert_eq!(
            totals.combined(&other),
            UsageTotals {
                call_attempts: 3,
                usage: Usage {
                    input_tokens: Some(45),
                    output_tokens: Some(23),
                    total_tokens: Some(79),
                },
            }
        );
        assert_eq!(totals.call_attempts, 2);
        assert_eq!(totals.usage.total_tokens, Some(70));
        assert_eq!(other.call_attempts, 1);
        assert_eq!(other.usage.total_tokens, Some(9));
    }

    #[test]
    fn usage_unknown_counts() {
        let mut totals = UsageTotals::default();
        totals.record(Some(&Usage {
            input_tokens: Some(20),
            output_tokens: None,
            total_tokens: Some(35),
        }));
        let usage = Usage {
            input_tokens: Some(10),
            output_tokens: Some(5),
            total_tokens: Some(15),
        };
        totals.record(Some(&usage));
        assert_eq!(totals.usage.input_tokens, Some(30));
        assert_eq!(totals.usage.output_tokens, None);
        assert_eq!(totals.usage.total_tokens, Some(50));

        let mut failed = UsageTotals::default();
        failed.record(None);
        failed.record(Some(&usage));
        assert_eq!(
            totals.combined(&failed),
            UsageTotals {
                call_attempts: 4,
                usage: Usage {
                    input_tokens: None,
                    output_tokens: None,
                    total_tokens: None,
                },
            }
        );
        assert_eq!(totals.usage.input_tokens, Some(30));
        assert_eq!(totals.usage.total_tokens, Some(50));
    }

    #[cfg(feature = "ldk")]
    #[test]
    fn shared_usage_tracker() {
        #[derive(Clone, Default)]
        struct Accounting {
            label: String,
            first: UsageTotals,
            second: UsageTotals,
        }

        let tracker = UsageTracker::<Accounting>::default();
        let observer = tracker.clone();
        let initialized = tracker.record(|state| state.label = "session".into());
        assert_eq!(initialized.first.call_attempts, 0);
        assert_eq!(initialized.second.call_attempts, 0);

        let usage = Usage {
            input_tokens: Some(20),
            output_tokens: Some(10),
            total_tokens: Some(35),
        };
        let first = tracker.record(|state| state.first.record(Some(&usage)));
        let second = observer.record(|state| state.second.record(Some(&usage)));
        assert_eq!(first.first.call_attempts, 1);
        assert_eq!(first.second.call_attempts, 0);
        assert_eq!(second.label, "session");
        assert_eq!(second.first, first.first);
        assert_eq!(second.second.call_attempts, 1);
        let total = second.first.combined(&second.second);
        assert_eq!(total.call_attempts, 2);
        assert_eq!(total.usage.total_tokens, Some(70));

        let mut snapshot = observer.snapshot();
        snapshot.first.record(None);
        snapshot.label.clear();
        let current = tracker.snapshot();
        assert_eq!(current.first, second.first);
        assert_eq!(current.second, second.second);
        assert_eq!(current.label, "session");
        assert_eq!(UsageTracker::<Accounting>::default().snapshot().first.call_attempts, 0);
    }

    #[cfg(feature = "ldk")]
    #[test]
    fn usage_on_preparation_failure() {
        use backend::openai_compat::{OpenAiCompatBackend, WebSearchOptions};

        fn assert_send_sync(_: &(impl Send + Sync)) {}

        let backend = OpenAiCompatBackend::chat_completions("test", "unused").web_search(WebSearchOptions::default());
        let request = ModelRequest::new("test-model", "test prompt");
        let expected = backend.prepare_request(&request).unwrap_err().to_string();
        let tracker = UsageTracker::<UsageTotals>::default();
        let recorder = tracker.clone();
        let observed = with_usage_observer(backend, move |usage| {
            recorder.record(|totals| totals.record(usage));
        });
        assert_send_sync(&observed);
        let model = ModelConfig::new("test-model", observed);
        assert_eq!(call_model(&model, &request).unwrap_err().to_string(), expected);
        assert_eq!(tracker.snapshot().call_attempts, 1);
        assert_eq!(tracker.snapshot().usage.total_tokens, None);
        assert_eq!(call_model(&model.clone(), &request).unwrap_err().to_string(), expected);
        assert_eq!(tracker.snapshot().call_attempts, 2);
    }

    #[test]
    fn usage_observer_delegation() {
        use std::{cell::RefCell, rc::Rc};

        let backend = backend::openai_compat::OpenAiCompatBackend::responses("test", "unused");
        let request = ModelRequest::new("test-model", "test prompt").max_output_tokens(8192);
        let expected_request = backend.prepare_request(&request).unwrap();
        let response = JsonApiResponse {
            http: http::Response {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
            },
            json: serde_json::json!({
                "status": "incomplete",
                "incomplete_details": {"reason": "max_output_tokens"},
                "usage": {"input_tokens": 20, "output_tokens": 10, "total_tokens": 35},
            }),
        };
        let expected_response = backend.parse_response(response.clone()).unwrap();
        let reports = Rc::new(RefCell::new(Vec::new()));
        let inner_reports = reports.clone();
        let inner = with_usage_observer(backend, move |usage| {
            inner_reports.borrow_mut().push(("inner", usage.cloned()));
        });
        let outer_reports = reports.clone();
        let model = ModelConfig::new(
            "test-model",
            with_usage_observer(inner, move |usage| {
                outer_reports.borrow_mut().push(("outer", usage.cloned()));
            }),
        );
        assert_eq!(model.prepare_request(&request).unwrap(), expected_request);
        let parsed = model.parse_response(response).unwrap();
        assert_eq!(parsed, expected_response);
        assert!(parsed.text.is_none());
        assert_eq!(parsed.finish_reason, Some(FinishReason::Length));
        assert!(reports.borrow().is_empty());
        model.clone().on_usage(parsed.usage.as_ref());
        assert_eq!(
            *reports.borrow(),
            vec![("inner", parsed.usage.clone()), ("outer", parsed.usage)]
        );
    }

    #[test]
    fn invalid_json_keeps_body() {
        // A 200 with a non-JSON body has no status-line signal — the body is the only diagnostic,
        // so the error (and its Display) must carry it.
        let response = http::Response {
            status: 200,
            headers: Vec::new(),
            body: b"<<not json at all>>".to_vec(),
        };
        let err = JsonApiResponse::from_http("openai", 200, response).expect_err("malformed JSON must error");
        match &err {
            LlmError::ResponseDecode { provider, body, .. } => {
                assert_eq!(provider, "openai");
                assert!(
                    body.contains("<<not json at all>>"),
                    "body must carry the payload, got: {body:?}"
                );
            }
            other => panic!("expected ResponseDecode, got: {other:?}"),
        }
        assert!(
            err.to_string().contains("<<not json at all>>"),
            "Display must surface the body, got: {err}"
        );
    }
}
