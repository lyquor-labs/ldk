use crate::{JsonApiResponse, LlmResult, ModelRequest, ModelResponse, PreparedJsonApiRequest};

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
}
