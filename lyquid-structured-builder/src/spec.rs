use std::any::Any;
use std::collections::BTreeSet;
use std::sync::Arc;

use lyquid_flow::{BuildError, Diagnostic, Flow, Step};
use serde::{Deserialize, Serialize};
use tera::Tera;
use typed_builder::TypedBuilder;

use crate::{NextStep, StructuredStep, ValueSource, nonblank};

/// Structured rules for an existing Step.
///
/// Construct directly, with the derived builder, or from JSON. All forms are validated by `with`.
#[derive(Clone, Default, Deserialize, Serialize, TypedBuilder)]
#[builder(field_defaults(default))]
#[serde(default, deny_unknown_fields)]
pub struct StructuredSpec {
    /// Field updates applied after the native finalizer; model criteria require a native model template.
    /// References and criteria read the current committed State, without pending updates.
    pub state_updates: Vec<(String, ValueSource)>,
    /// Replaces model next-Step choices and the final route; omission preserves the native finalizer's route.
    #[builder(setter(strip_option))]
    pub next: Option<NextStep>,
}

impl StructuredSpec {
    /// Validates these rules and wraps an existing Step. Wrapping a Flow is unsupported.
    pub fn with(self, inner: impl Step + 'static) -> Result<StructuredStep, BuildError> {
        if (&inner as &dyn Any).is::<Flow>() {
            return Err(Diagnostic::new("StructuredSpec", "cannot wrap a Flow; mount it with FlowBuilder::flow").into());
        }
        let mut templates = Vec::new();
        let mut fields = BTreeSet::new();
        for (field, value) in &self.state_updates {
            nonblank(field, "State update")?;
            if !fields.insert(field) {
                return Err(Diagnostic::new(format!("State update {field:?}"), "duplicate State update").into());
            }
            value.validate()?;
            if let ValueSource::Model { description } = value {
                templates.push((field.as_str(), description));
            }
        }
        if let Some(next) = &self.next {
            if next.steps.is_empty() {
                return Err(Diagnostic::new("next", "at least one next Step is required").into());
            }
            let mut targets = BTreeSet::new();
            for case in &next.steps {
                if let Some(next) = &case.next {
                    nonblank(&next.0, "next Step")?;
                }
                if !targets.insert(case.next.as_ref()) {
                    return Err(Diagnostic::new("next", "duplicate next Step").into());
                }
                nonblank(&case.description, "next Step description")?;
                templates.push(("next", &case.description));
            }
        }
        for (label, text) in templates {
            Tera::default()
                .add_raw_template("check", text)
                .map_err(|error| Diagnostic::with_source(format!("invalid {label} template"), error))?;
        }
        Ok(StructuredStep {
            inner: Arc::new(inner),
            spec: self,
        })
    }
}
