#![doc(html_no_source)] // remove it upon open-source

//! Provider-neutral LLM request and response adapters for Lyquid instance functions.
//! With the `ldk` feature, `call_model` sends requests through `lyquor_api::http_request`.

/// Provider-specific request and response adapters.
pub mod backend;

mod error;
mod types;

pub use backend::Backend;
pub use error::{LlmError, LlmResult};
pub use types::{
    FinishReason, JsonApiRequest, JsonApiResponse, ModelRequest, ModelResponse, PreparedJsonApiRequest, Usage,
};

/// Call a model from a Lyquid WASM guest using the backend's prepared HTTP request.
#[cfg(feature = "ldk")]
pub fn call_model<B: Backend + ?Sized>(backend: &B, request: &ModelRequest) -> LlmResult<ModelResponse> {
    let prepared = backend.prepare_request(request)?;
    let response = lyquid::runtime::lyquor_api::http_request(prepared.request, prepared.options).map_err(|source| {
        LlmError::Transport {
            provider: prepared.provider.clone(),
            source,
        }
    })?;
    let response = JsonApiResponse::from_http(prepared.provider, prepared.expected_status, response)?;
    backend.parse_response(response)
}
