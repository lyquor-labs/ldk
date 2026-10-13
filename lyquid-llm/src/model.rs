use std::sync::Arc;

use serde_json::{Map, Value};

use crate::{
    Backend, JsonApiResponse, LlmError, LlmResult, ModelRequest, ModelResponse, OutputFormat, PreparedJsonApiRequest,
    Usage,
    backend::{
        gemini::GeminiBackend,
        openai_compat::{OpenAiCompatBackend, ReasoningEffort, Verbosity},
    },
};

/// Model selection, shared request defaults, and a provider adapter.
#[derive(Clone)]
pub struct ModelConfig {
    model: String,
    backend: Arc<dyn Backend>,
    max_output_tokens: Option<u16>,
    request_body_fields: Map<String, Value>,
}

impl ModelConfig {
    /// Configure any backend, including custom adapters and deterministic test backends.
    pub fn new<B: Backend + 'static>(model: impl Into<String>, backend: B) -> Self {
        Self {
            model: model.into(),
            backend: Arc::new(backend),
            max_output_tokens: None,
            request_body_fields: Map::new(),
        }
    }

    /// Declare an OpenAI Responses model. Credentials are validated by [`ModelBuilder::build`].
    pub fn openai(model: impl Into<String>, api_key: impl Into<String>) -> ModelBuilder {
        ModelBuilder::new(Provider::OpenAi, model.into(), api_key.into())
    }

    /// Declare a Gemini generateContent model. Credentials are validated by [`ModelBuilder::build`].
    pub fn gemini(model: impl Into<String>, api_key: impl Into<String>) -> ModelBuilder {
        ModelBuilder::new(Provider::Gemini, model.into(), api_key.into())
    }

    /// The model selected by this configuration.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Set the maximum output-token budget for every request using this configuration.
    pub fn max_output_tokens(mut self, max_output_tokens: u16) -> Self {
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    /// Add a provider-specific JSON field to every request using this configuration.
    pub fn request_body_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.request_body_fields.insert(key.into(), value);
        self
    }
}

impl Backend for ModelConfig {
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
        let mut request = request.clone();
        request.model.clone_from(&self.model);
        if let Some(max_output_tokens) = self.max_output_tokens {
            request.max_output_tokens = Some(max_output_tokens);
        }
        request.extra_body.extend(self.request_body_fields.clone());
        self.backend.prepare_request(&request)
    }

    fn parse_response(&self, response: JsonApiResponse) -> LlmResult<ModelResponse> {
        self.backend.parse_response(response)
    }

    fn on_usage(&self, usage: Option<&Usage>) {
        self.backend.on_usage(usage);
    }
}

#[derive(Clone, Copy)]
enum Provider {
    OpenAi,
    Gemini,
}

/// A declarative built-in model configuration. Building performs local validation, never HTTP.
/// OpenAI-only reasoning and verbosity options are rejected when building a Gemini model.
#[derive(Clone)]
pub struct ModelBuilder {
    provider: Provider,
    model: String,
    api_key: String,
    output_format: Option<OutputFormat>,
    reasoning_effort: Option<ReasoningEffort>,
    verbosity: Option<Verbosity>,
}

impl ModelBuilder {
    fn new(provider: Provider, model: String, api_key: String) -> Self {
        Self {
            provider,
            model,
            api_key,
            output_format: None,
            reasoning_effort: None,
            verbosity: None,
        }
    }

    /// Set an explicit output format. Leaving it unset preserves the provider's default.
    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = Some(format);
        self
    }

    /// Request JSON without a schema constraint.
    pub fn json_mode(self) -> Self {
        self.output_format(OutputFormat::Json)
    }

    /// Request schema-constrained JSON; OpenAI uses strict mode.
    pub fn json_schema(self, name: impl Into<String>, schema: Value) -> Self {
        self.output_format(OutputFormat::json_schema(name, schema))
    }

    /// Set an OpenAI reasoning effort. Support depends on the selected model.
    pub fn reasoning_effort(mut self, effort: ReasoningEffort) -> Self {
        self.reasoning_effort = Some(effort);
        self
    }

    /// Set OpenAI output verbosity. Support depends on the selected model.
    pub fn verbosity(mut self, verbosity: Verbosity) -> Self {
        self.verbosity = Some(verbosity);
        self
    }

    /// Validate this declaration and construct its provider adapter.
    pub fn build(self) -> LlmResult<ModelConfig> {
        if self.model.trim().is_empty() {
            return Err(configuration_error(self.provider, "the model must not be empty"));
        }
        Ok(match self.provider {
            Provider::OpenAi => {
                let mut backend = OpenAiCompatBackend::openai(&self.api_key)?;
                if let Some(effort) = self.reasoning_effort {
                    backend = backend.reasoning_effort(effort);
                }
                if let Some(verbosity) = self.verbosity {
                    backend = backend.verbosity(verbosity);
                }
                if let Some(format) = self.output_format {
                    backend = backend.output_format(format);
                }
                ModelConfig::new(self.model, backend)
            }
            Provider::Gemini => {
                if self.reasoning_effort.is_some() || self.verbosity.is_some() {
                    return Err(configuration_error(
                        self.provider,
                        "reasoning_effort and verbosity are OpenAI-only options",
                    ));
                }
                let mut backend = GeminiBackend::google_ai(&self.api_key)?;
                if let Some(format) = self.output_format {
                    backend = backend.output_format(format);
                }
                ModelConfig::new(self.model, backend)
            }
        })
    }
}

fn configuration_error(provider: Provider, message: &str) -> LlmError {
    LlmError::Backend {
        provider: match provider {
            Provider::OpenAi => "openai",
            Provider::Gemini => "gemini",
        }
        .into(),
        message: message.into(),
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

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": false
        })
    }

    #[test]
    fn openai_builder() {
        let model = ModelConfig::openai("gpt-5.4", "fixture-key")
            .reasoning_effort(ReasoningEffort::None)
            .verbosity(Verbosity::Low)
            .json_schema("answer", schema())
            .build()
            .unwrap()
            .max_output_tokens(8192);
        let output = body(
            &model,
            &ModelRequest::new("overridden", "Return JSON").max_output_tokens(7),
        );
        assert_eq!(model.model(), "gpt-5.4");
        assert_eq!(output["model"], "gpt-5.4");
        assert_eq!(output["max_output_tokens"], 8192);
        assert_eq!(output["reasoning"]["effort"], "none");
        assert_eq!(output["text"]["verbosity"], "low");
        assert_eq!(output["text"]["format"]["strict"], true);
        assert_eq!(output["text"]["format"]["schema"], schema());
    }

    #[test]
    fn gemini_builder() {
        let model = ModelConfig::gemini("gemini-2.5-flash", "fixture-key")
            .json_mode()
            .build()
            .unwrap()
            .max_output_tokens(8192);
        let request = ModelRequest::new("overridden", "Return JSON").max_output_tokens(7);
        let prepared = model.prepare_request(&request).unwrap();
        assert_eq!(model.model(), "gemini-2.5-flash");
        assert!(prepared.request.url.ends_with("/gemini-2.5-flash:generateContent"));
        assert_eq!(
            body(&model, &request)["generationConfig"],
            json!({"maxOutputTokens": 8192, "responseMimeType": "application/json"})
        );
    }

    #[test]
    fn invalid_config() {
        for builder in [
            ModelConfig::openai("gpt-5.4", " "),
            ModelConfig::gemini("gemini-2.5-flash", " "),
            ModelConfig::openai(" ", "fixture-key"),
            ModelConfig::gemini(" ", "fixture-key"),
        ] {
            assert!(builder.build().is_err());
        }
        assert!(
            ModelConfig::gemini("gemini-2.5-flash", "fixture-key")
                .reasoning_effort(ReasoningEffort::Low)
                .build()
                .is_err()
        );
        assert!(
            ModelConfig::gemini("gemini-2.5-flash", "fixture-key")
                .verbosity(Verbosity::Low)
                .build()
                .is_err()
        );
    }

    #[test]
    fn custom_backend() {
        let backend = OpenAiCompatBackend::responses("custom", "https://model.example/responses")
            .output_format(OutputFormat::Json);
        let model = ModelConfig::new("custom-model", backend)
            .max_output_tokens(8192)
            .request_body_field("text", json!({"format": {"type": "text"}}));
        let request = ModelRequest::new("ignored", "prompt")
            .max_output_tokens(7)
            .body_field("text", json!({"format": {"type": "json_object"}}));
        let output = body(&model, &request);
        assert_eq!(output["model"], "custom-model");
        assert_eq!(output["max_output_tokens"], 8192);
        assert_eq!(output["text"]["format"]["type"], "text");
        let response = model
            .parse_response(crate::JsonApiResponse {
                http: lyquid::http::Response {
                    status: 200,
                    headers: vec![],
                    body: vec![],
                },
                json: json!({"output_text": "answer"}),
            })
            .unwrap();
        assert_eq!(response.text.as_deref(), Some("answer"));
    }

    #[test]
    fn string_errors() {
        fn application_config() -> Result<ModelConfig, String> {
            Ok(ModelConfig::openai("gpt-5.4", "").build()?)
        }
        assert!(application_config().err().unwrap().contains("API key"));
    }
}
