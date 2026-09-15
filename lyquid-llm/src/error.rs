//! Error type for `lyquid-llm` operations.
//!
//! Covers provider request encoding, Lyquid host transport, HTTP status handling, response
//! decoding, and backend-specific response validation.

use thiserror::Error;

/// Maximum bytes of an unexpected response body to keep in [`LlmError::UnexpectedStatus`].
/// LLM providers often return long HTML / JSON error pages; capping prevents log explosion
/// while keeping enough to diagnose the failure (the meaningful prefix usually fits in 2 KiB).
const UNEXPECTED_STATUS_BODY_CAP: usize = 2048;

/// Captures a (possibly truncated) HTTP response body for diagnostic surfacing in
/// [`LlmError::UnexpectedStatus`]. Decodes as UTF-8-lossy and caps at
/// [`UNEXPECTED_STATUS_BODY_CAP`] bytes; appends a `[truncated, N more bytes]` marker if
/// truncation happens, so a log reader knows whether they're seeing the full thing.
pub fn capture_status_body(body: &[u8]) -> String {
    if body.len() <= UNEXPECTED_STATUS_BODY_CAP {
        return String::from_utf8_lossy(body).into_owned();
    }
    let head = String::from_utf8_lossy(&body[..UNEXPECTED_STATUS_BODY_CAP]).into_owned();
    let extra = body.len() - UNEXPECTED_STATUS_BODY_CAP;
    format!("{head}[truncated, {extra} more bytes]")
}

/// Errors produced by `lyquid-llm` request preparation and response parsing.
#[derive(Debug, Error)]
pub enum LlmError {
    /// Failed to serialize a request body to JSON. Includes the provider tag for debuggability.
    #[error("{provider}: failed to serialize request body: {source}")]
    RequestEncode {
        provider: String,
        #[source]
        source: serde_json::Error,
    },
    /// HTTP transport returned a status the backend wasn't expecting (e.g., 401, 429, 500).
    /// Carries the truncated response body — usually the most useful field for diagnosing what
    /// the provider actually said. Provider error responses (rate-limit reasons, malformed-
    /// request hints, model-unavailable messages) live in the body, not the status line.
    #[error("{provider}: unexpected HTTP status {status}: {body}")]
    UnexpectedStatus {
        provider: String,
        status: u16,
        body: String,
    },
    /// The Lyquid host HTTP transport failed before a provider response was available.
    #[error("{provider}: HTTP transport error: {source}")]
    Transport {
        provider: String,
        #[source]
        source: lyquid::LyquidError,
    },
    /// Response body wasn't valid JSON, or didn't decode into the expected ABI shape. Carries the
    /// (truncated) body — for a 200 + malformed-JSON response there is no status-line signal, so
    /// the offending payload is the most useful field for diagnosing what the provider returned.
    #[error("{provider}: failed to parse response body: {source}; body: {body}")]
    ResponseDecode {
        provider: String,
        body: String,
        #[source]
        source: serde_json::Error,
    },
    /// Backend logic rejected the response (missing required field, etc.). Free-form because
    /// the per-backend variants would otherwise leak into this enum.
    #[error("{provider}: {message}")]
    Backend { provider: String, message: String },
}

/// Convenience alias used throughout the crate.
pub type LlmResult<T> = Result<T, LlmError>;

impl From<LlmError> for lyquid::LyquidError {
    fn from(e: LlmError) -> Self {
        Self::LyquorRuntime(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_short_body_is_full() {
        let body = b"{\"error\":\"invalid_api_key\"}";
        assert_eq!(capture_status_body(body), "{\"error\":\"invalid_api_key\"}");
    }

    #[test]
    fn capture_long_body_truncates_with_marker() {
        let body = vec![b'x'; UNEXPECTED_STATUS_BODY_CAP + 100];
        let captured = capture_status_body(&body);
        assert!(captured.starts_with("xxxx"));
        assert!(
            captured.contains("[truncated, 100 more bytes]"),
            "must report how many bytes were dropped, got: {}",
            &captured[captured.len().saturating_sub(80)..]
        );
    }

    #[test]
    fn capture_handles_non_utf8() {
        // 0xff is invalid UTF-8 — must not panic; comes through as the replacement char.
        let captured = capture_status_body(&[0xff, b'h', b'i']);
        assert!(captured.ends_with("hi"));
    }
}
