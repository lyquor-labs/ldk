//! Deterministic, single-selection input with any number of configured destinations.

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
}

impl Step for MultipleChoiceStep {
    fn description(&self, _concise: bool) -> String {
        "Choose one option and follow its configured destination".to_owned()
    }

    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        let mut builder = InputSpec::builder();
        let choice = builder
            .field(&self.field, (self.prompt)(scope), String::new())
            .choices(
                self.choices
                    .iter()
                    .map(|choice| (choice.id.clone(), choice.label.clone())),
            )
            .select_one();
        let submit = builder.submit("Choose");
        let layout = builder.ui().column(vec![choice, submit]);
        Some(builder.finish(layout).expect("validated choice declaration"))
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

#[cfg(test)] mod tests;
