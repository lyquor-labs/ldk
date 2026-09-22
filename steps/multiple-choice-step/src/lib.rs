//! Deterministic, single-selection input with any number of configured destinations.

use std::fmt::Write as _;
use std::sync::Arc;

use lyquid_flow::{
    FlowError, InputSpec, Scope, StateNamespace, StateUpdates, Step, StepId, TemplateSpec, TraceSummary, TurnProposal,
};

/// An application-owned option. The user submits its ID, never a destination Step ID.
#[derive(Clone)]
pub struct Choice {
    pub id: String,
    pub label: String,
    pub next: StepId,
}

impl Choice {
    pub fn new(id: impl Into<String>, label: impl Into<String>, next: impl Into<StepId>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            next: next.into(),
        }
    }
}

/// Collects one option ID, commits it to a declared String State field, and follows its route.
/// Options are fixed at construction and can share a destination. No model or fixed option count is assumed.
pub struct MultipleChoiceStep {
    field: String,
    prompt: Arc<dyn Fn(&Scope) -> String + Send + Sync>,
    choices: Vec<Choice>,
}

impl MultipleChoiceStep {
    pub fn new(field: impl Into<String>, prompt: impl Into<String>, choices: Vec<Choice>) -> Result<Self, FlowError> {
        validate_choices(&choices)?;
        let prompt = prompt.into();
        Ok(Self {
            field: field.into(),
            prompt: Arc::new(move |_| prompt.clone()),
            choices,
        })
    }

    pub fn with_prompt(mut self, prompt: impl Fn(&Scope) -> String + Send + Sync + 'static) -> Self {
        self.prompt = Arc::new(prompt);
        self
    }

    /// Returns the fixed options. Copy them for rendering before moving this Step into a Flow.
    pub fn choices(&self) -> &[Choice] {
        &self.choices
    }
}

impl Step for MultipleChoiceStep {
    fn description(&self, _concise: bool) -> String {
        "Choose one option and follow its configured destination".to_owned()
    }

    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        let mut prompt = (self.prompt)(scope);
        for choice in &self.choices {
            write!(&mut prompt, "\n- {}: {}", choice.id, choice.label).expect("writing to a String cannot fail");
        }
        Some(InputSpec {
            name: self.field.clone(),
            prompt,
            value: Box::new(String::new()),
        })
    }

    fn model_template(&self, _scope: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: None,
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let TurnProposal::Advance { next, updates } = proposal else {
            return Err(FlowError::Execution(
                "multiple choice does not allow restore proposals".to_owned(),
            ));
        };
        let id = scope
            .get::<String>(StateNamespace::Input, &self.field)
            .ok_or_else(|| FlowError::Execution(format!("missing or incorrectly typed choice input {}", self.field)))?;
        let choice = self
            .choices
            .iter()
            .find(|choice| choice.id == *id)
            .ok_or_else(|| FlowError::Execution(format!("unknown choice {id:?}")))?;
        *updates = StateUpdates::default();
        updates.set(self.field.clone(), Some(Box::new(id.clone())));
        *next = Some(choice.next.clone());
        Ok(TraceSummary::Summary(format!("Chose {}", choice.id)))
    }
}

fn validate_choices(choices: &[Choice]) -> Result<(), FlowError> {
    if choices.is_empty() {
        return Err(FlowError::Execution(
            "multiple choice requires at least one option".to_owned(),
        ));
    }
    for (index, choice) in choices.iter().enumerate() {
        if choice.id.trim().is_empty() || choice.label.trim().is_empty() || choice.next.0.trim().is_empty() {
            return Err(FlowError::Execution(
                "choice IDs, labels, and destinations must not be empty".to_owned(),
            ));
        }
        if choices[..index].iter().any(|other| other.id == choice.id) {
            return Err(FlowError::Execution(format!("duplicate choice ID {:?}", choice.id)));
        }
    }
    Ok(())
}

/// Accessible, unstyled single-choice buttons. The application submits the clicked button's value.
/// Pass the pending input contract and the fixed options retained before mounting the Step.
pub fn render_html(spec: &InputSpec, choices: &[Choice]) -> String {
    let mut html = format!(
        "<form data-step=\"multiple-choice\"><fieldset><legend>{}</legend>",
        escape_html(&spec.prompt)
    );
    for choice in choices {
        write!(
            &mut html,
            "<button type=\"submit\" name=\"{}\" value=\"{}\">{}</button>",
            escape_html(&spec.name),
            escape_html(&choice.id),
            escape_html(&choice.label)
        )
        .expect("writing to a String cannot fail");
    }
    html.push_str("</fieldset></form>");
    html
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)] mod tests;
