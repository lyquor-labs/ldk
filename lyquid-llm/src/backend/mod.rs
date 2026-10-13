use crate::{JsonApiResponse, LlmError, LlmResult, ModelRequest, ModelResponse, PreparedJsonApiRequest, Usage};

/// Gemini-compatible request preparation and response parsing.
pub mod gemini;
/// OpenAI-compatible Responses and Chat Completions adapters.
pub mod openai_compat;

/// Provider adapter that prepares requests and parses JSON responses.
pub trait Backend {
    /// Convert a provider-neutral model request into a JSON HTTP request.
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest>;
    /// Convert a JSON HTTP response into a provider-neutral model response.
    fn parse_response(&self, response: JsonApiResponse) -> LlmResult<ModelResponse>;
    /// Receives usage once after each `call_model` attempt, before application output validation.
    /// `None` means the attempt failed or the provider omitted usage. Request preparation and
    /// response parsing do not invoke this hook themselves. Wrappers should forward it.
    fn on_usage(&self, _usage: Option<&Usage>) {}
}

fn required_api_key<'a>(provider: &str, api_key: &'a str) -> LlmResult<&'a str> {
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err(LlmError::Backend {
            provider: provider.into(),
            message: "the API key must not be empty".into(),
        });
    }
    Ok(api_key)
}
