//! Convenience helpers for JSON AI provider requests from Lyquid instance functions.
//!
//! This module intentionally stays provider-schema agnostic. Lyquids own the OpenAI, Gemini,
//! Anthropic, or other provider request bodies, while the SDK handles the repeated JSON POST
//! mechanics around headers, timeout, status validation, and response parsing.

use crate::{LyquidError, LyquidResult, http};

const APPLICATION_JSON: &[u8] = b"application/json";

#[derive(Clone, Debug, PartialEq)]
pub struct JsonApiRequest {
    provider: String,
    url: String,
    headers: Vec<http::Header>,
    body: serde_json::Value,
    timeout_ms: Option<u64>,
    expected_status: u16,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JsonApiResponse {
    pub http: http::Response,
    pub json: serde_json::Value,
}

impl JsonApiRequest {
    pub fn post(provider: impl Into<String>, url: impl Into<String>, body: serde_json::Value) -> Self {
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

    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    pub fn expected_status(mut self, status: u16) -> Self {
        self.expected_status = status;
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push(http::Header {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    pub fn headers(mut self, headers: impl IntoIterator<Item = http::Header>) -> Self {
        self.headers.extend(headers);
        self
    }

    pub fn bearer_auth(self, token: &str) -> Self {
        self.header("Authorization", format!("Bearer {}", token.trim()))
    }

    pub fn api_key_header(self, name: impl Into<String>, api_key: &str) -> Self {
        self.header(name, api_key.trim().as_bytes().to_vec())
    }

    pub fn into_http_request(self) -> LyquidResult<http::Request> {
        let body = serde_json::to_vec(&self.body)
            .map_err(|e| LyquidError::LyquorRuntime(format!("{} request json error: {e}", self.provider)))?;

        Ok(http::Request {
            method: http::Method::Post,
            url: self.url,
            headers: self.headers,
            body: Some(body),
        })
    }

    pub fn send(self) -> LyquidResult<JsonApiResponse> {
        let provider = self.provider.clone();
        let expected_status = self.expected_status;
        let options = self.timeout_ms.map(|timeout_ms| http::RequestOptions {
            timeout_ms: Some(timeout_ms),
        });
        let request = self.into_http_request()?;
        let response = crate::runtime::lyquor_api::http_request(request, options)?;

        if response.status != expected_status {
            return Err(LyquidError::LyquorRuntime(format!(
                "{provider} http status {}",
                response.status
            )));
        }

        let json = serde_json::from_slice(&response.body)
            .map_err(|e| LyquidError::LyquorRuntime(format!("{provider} response parse error: {e}")))?;

        Ok(JsonApiResponse { http: response, json })
    }
}
