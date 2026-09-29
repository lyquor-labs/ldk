//! Text entry as a deterministic Step, separate from model-backed processing.
//!
//! The Step describes its text field through `InputSpec`. The application presents that UI and
//! submits a JSON field object through `InputHandle::submit_input()`.

use std::sync::Arc;

use lyquid_flow::{
    FlowError, InputSpec, Scope, StateNamespace, StateUpdates, Step, StepId, TemplateSpec, TraceSummary, TurnProposal,
};

/// Collects text and commits it to one declared State field without calling a model.
///
/// The field name is also the ephemeral input binding. The destination field must already exist
/// and have type `String`. This Step stores the text unchanged and never interprets commands.
pub struct TextInputStep {
    field: String,
    prompt: Arc<dyn Fn(&Scope) -> String + Send + Sync>,
    next: StepId,
}

impl TextInputStep {
    pub fn new(field: impl Into<String>, prompt: impl Into<String>, next: impl Into<StepId>) -> Self {
        let prompt = prompt.into();
        Self {
            field: field.into(),
            prompt: Arc::new(move |_| prompt.clone()),
            next: next.into(),
        }
    }

    /// Computes the prompt from the current Scope whenever this Step requests input.
    /// The callback can read committed State populated by earlier Steps.
    pub fn with_prompt(mut self, prompt: impl Fn(&Scope) -> String + Send + Sync + 'static) -> Self {
        self.prompt = Arc::new(prompt);
        self
    }
}

impl Step for TextInputStep {
    fn description(&self, _concise: bool) -> String {
        "Collect a text message".to_owned()
    }

    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        let mut builder = InputSpec::builder();
        let text = builder
            .field(&self.field, (self.prompt)(scope), String::new())
            .text_input();
        let submit = builder.submit("Send");
        let layout = builder.ui().column(vec![text, submit]);
        Some(builder.finish(layout).expect("valid text input declaration"))
    }

    fn model_template(&self, _scope: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some(self.next.clone()),
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let TurnProposal::Advance { next, updates } = proposal else {
            return Err(FlowError::Execution(
                "text input does not allow restore proposals".to_owned(),
            ));
        };
        let value = scope
            .get::<String>(StateNamespace::Input, &self.field)
            .ok_or_else(|| FlowError::Execution(format!("missing or incorrectly typed text input {}", self.field)))?;
        *updates = StateUpdates::default();
        updates.set(self.field.clone(), Some(Box::new(value.clone())));
        *next = Some(self.next.clone());
        Ok(TraceSummary::Summary("Received a text message".to_owned()))
    }
}

#[cfg(test)] mod tests;
