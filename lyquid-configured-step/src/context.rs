//! Read-only inputs shared by every finalization action in one Step execution.

use std::ops::Deref;

use lyquid_llm::{FinishReason, ModelResponse};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

/// Prepared arguments and temporary execution data available to a finalization action.
/// Named results contain only successful earlier actions and are discarded after this turn.
/// Dereferencing reads the prepared context, preserving convenient typed field access.
pub struct ActionContext<'a, C> {
    prepared: &'a C,
    model_response: Option<&'a ModelResponse>,
    results: &'a Map<String, Value>,
    proposals: Option<&'a Map<String, Value>>,
}

impl<'a, C> ActionContext<'a, C> {
    /// Creates a borrowed view, also useful when calling an action outside a Step.
    pub fn new(prepared: &'a C, model_response: Option<&'a ModelResponse>, results: &'a Map<String, Value>) -> Self {
        Self {
            prepared,
            model_response,
            results,
            proposals: None,
        }
    }

    pub fn prepared(&self) -> &C {
        self.prepared
    }

    /// Original response and metadata from this Step's model phase, if one ran.
    pub fn model_response(&self) -> Option<&ModelResponse> {
        self.model_response
    }

    /// Reads a named earlier action's saved JSON output, independently of the previous result.
    pub fn result(&self, name: &str) -> Option<&Value> {
        self.results.get(name)
    }

    /// Reads a validated model proposal by its Step-local name, independently of State bindings.
    pub fn proposed<T: DeserializeOwned>(&self, name: &str) -> Result<T, String> {
        let value = self
            .proposals
            .and_then(|values| values.get(name))
            .ok_or_else(|| format!("missing model output {name:?}"))?;
        serde_json::from_value(value.clone()).map_err(|e| format!("decode model output {name:?}: {e}"))
    }

    pub(super) fn with_proposals(mut self, proposals: &'a Map<String, Value>) -> Self {
        self.proposals = Some(proposals);
        self
    }

    /// Renders an action-owned text template once. Earlier named outputs and the model response
    /// are available alongside the typed `context`; the current action's result is not yet available.
    pub fn render(&self, template: &str) -> Result<String, String>
    where
        C: Serialize,
    {
        let mut context = tera::Context::new();
        context.insert("context", self.prepared);
        context.insert("actions", self.results);
        context.insert("model_response", &self.model_response.map(model_response_json));
        context.insert("proposals", &self.proposals);
        tera::Tera::one_off(template, &context, false).map_err(|e| format!("render action template: {e}"))
    }
}

impl<C> Deref for ActionContext<'_, C> {
    type Target = C;

    fn deref(&self) -> &C {
        self.prepared
    }
}

// ModelResponse has no Serde representation in lyquid-llm. This view is the binding/template API.
pub(super) fn model_response_json(response: &ModelResponse) -> Value {
    let finish_reason = response.finish_reason.as_ref().map(|reason| match reason {
        FinishReason::Stop => json!("stop"),
        FinishReason::Length => json!("length"),
        FinishReason::ToolCalls => json!("tool_calls"),
        FinishReason::ContentFilter => json!("content_filter"),
        FinishReason::Other(reason) => json!({"other": reason}),
    });
    let usage = response.usage.as_ref().map(|usage| {
        json!({
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "total_tokens": usage.total_tokens,
        })
    });
    json!({
        "text": response.text,
        "finish_reason": finish_reason,
        "usage": usage,
        "web_search_used": response.web_search_used,
        "sources": response.sources,
        "raw_json": response.raw_json,
        "http": response.http,
    })
}
