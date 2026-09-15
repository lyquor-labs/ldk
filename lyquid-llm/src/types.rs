use serde_json::{Map, Value};

use crate::error::capture_status_body;
use crate::{LlmError, LlmResult};
use lyquid::http;

const APPLICATION_JSON: &[u8] = b"application/json";

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LlmError;

    #[test]
    fn from_http_200_with_bad_json_carries_body_in_error() {
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
