use std::fmt;

use lyquid::prelude::{HashMap, new_hashmap};
use serde_json::Value;

use crate::types::Type;
use crate::{BuildError, Diagnostic, FlowError};

/// Namespace for committed and in-flight State values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StateNamespace {
    /// Ordinary workflow State exposed under `state.<name>` in templates.
    Default,
    /// Input submitted by a user or another client.
    Input,
}

impl fmt::Display for StateNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Default => "default",
            Self::Input => "input",
        })
    }
}

/// Framework-owned JSON State with immutable structural declarations.
#[derive(Clone)]
pub struct State {
    pub(super) fields: HashMap<String, StateField>,
}

impl Default for State {
    fn default() -> Self {
        Self { fields: new_hashmap() }
    }
}

impl State {
    pub fn builder() -> StateBuilder {
        StateBuilder::default()
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.get(name).map(|field| &field.value)
    }

    pub fn declared_type(&self, name: &str) -> Option<&Type> {
        self.fields.get(name).map(|field| &field.declared_type)
    }

    /// Projects committed values into a JSON object, without declarations or staged updates.
    pub fn to_json(&self) -> Value {
        self.fields
            .iter()
            .map(|(name, field)| (name.clone(), field.value.clone()))
            .collect::<serde_json::Map<_, _>>()
            .into()
    }

    /// Checks every finalized replacement before any part of the turn is committed.
    pub(super) fn validate_updates(&self, updates: &StateUpdates) -> Result<(), FlowError> {
        for (name, value) in &updates.staging {
            let context = format!("State field {name}");
            let declaration = self
                .declared_type(name)
                .ok_or_else(|| Diagnostic::new(&context, "unknown field"))?;
            declaration
                .validate(value)
                .map_err(|error| Diagnostic::with_source(context, error))?;
        }
        Ok(())
    }

    pub(super) fn apply_updates(&mut self, updates: &StateUpdates) {
        for (name, value) in &updates.staging {
            self.fields
                .get_mut(name)
                .expect("StateUpdates fields are validated before commit")
                .value = value.clone();
        }
    }
}

/// Declares each State field's allowed type and initial JSON value explicitly.
#[derive(Default)]
pub struct StateBuilder {
    fields: Vec<(String, StateField)>,
}

impl StateBuilder {
    pub fn field(mut self, name: impl Into<String>, description: impl Into<String>, ty: Type, value: Value) -> Self {
        self.fields.push((
            name.into(),
            StateField {
                description: description.into(),
                declared_type: ty,
                value,
            },
        ));
        self
    }

    /// Rejects invalid initial values and duplicate declarations.
    pub fn build(self) -> Result<State, BuildError> {
        let mut state = State::default();
        for (name, field) in self.fields {
            let context = format!("State field {name}");
            field
                .declared_type
                .validate(&field.value)
                .map_err(|error| Diagnostic::with_source(&context, error))?;
            if state.fields.insert(name, field).is_some() {
                return Err(Diagnostic::new(context, "duplicate field").into());
            }
        }
        Ok(state)
    }
}

#[derive(Clone)]
pub(super) struct StateField {
    pub(super) description: String,
    pub(super) declared_type: Type,
    pub(super) value: Value,
}

/// Proposed JSON replacements and ephemeral input visible during a turn.
#[derive(Clone)]
pub struct StateUpdates {
    pub(super) staging: HashMap<String, Value>,
    pub(super) ephemeral: HashMap<String, Value>,
}

impl Default for StateUpdates {
    fn default() -> Self {
        Self {
            staging: new_hashmap(),
            ephemeral: new_hashmap(),
        }
    }
}

impl StateUpdates {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.get_in(StateNamespace::Default, name)
    }

    pub fn get_in(&self, namespace: StateNamespace, name: &str) -> Option<&Value> {
        let values = match namespace {
            StateNamespace::Default => &self.staging,
            StateNamespace::Input => &self.ephemeral,
        };
        values.get(name)
    }

    /// Stages a replacement; None removes the proposal, not the committed field.
    pub fn set(&mut self, name: String, value: Option<Value>) {
        self.set_in(StateNamespace::Default, name, value);
    }

    /// Staged values are checked at the Flow commit boundary. Input values are never committed.
    pub fn set_in(&mut self, namespace: StateNamespace, name: String, value: Option<Value>) {
        let values = match namespace {
            StateNamespace::Default => &mut self.staging,
            StateNamespace::Input => &mut self.ephemeral,
        };
        if let Some(value) = value {
            values.insert(name, value);
        } else {
            values.remove(&name);
        }
    }

    pub(super) fn merge(&mut self, updates: Self) {
        self.staging.extend(updates.staging);
    }
}

#[cfg(test)]
mod tests {
    use lyquid_test::test;
    use serde_json::json;

    use super::*;
    use StateNamespace::Input;

    #[test]
    fn commits_state_without_persisting_input() {
        let mut state = State::builder()
            .field("query", "Business value", Type::U64, json!(1))
            .build()
            .unwrap();
        let mut updates = StateUpdates::default();
        updates.set("query".into(), Some(json!(2)));
        updates.set_in(Input, "query".into(), Some(json!("coffee")));
        updates.set_in(Input, "input_only".into(), Some(json!(true)));
        assert_eq!(updates.get("query"), Some(&json!(2)));
        assert_eq!(updates.get_in(Input, "query"), Some(&json!("coffee")));
        state.validate_updates(&updates).unwrap();
        state.apply_updates(&updates);
        assert_eq!(state.to_json(), json!({"query": 2}));
    }

    #[test]
    fn merges_only_staged_updates_and_preserves_other_fields() {
        let mut updates = StateUpdates::default();
        updates.set("query".into(), Some(json!("old")));
        updates.set("limit".into(), Some(json!(3)));
        updates.set_in(Input, "query".into(), Some(json!("accepted")));
        let mut later = StateUpdates::default();
        later.set("query".into(), Some(json!("new")));
        later.set_in(Input, "query".into(), Some(json!("discarded")));
        later.set_in(Input, "input_only".into(), Some(json!(true)));
        updates.merge(later);
        assert_eq!(updates.get("query"), Some(&json!("new")));
        assert_eq!(updates.get("limit"), Some(&json!(3)));
        assert_eq!(updates.get_in(Input, "query"), Some(&json!("accepted")));
        assert!(updates.get_in(Input, "input_only").is_none());
    }

    #[test]
    fn removing_a_proposal_preserves_committed_state_and_other_inputs() {
        let mut state = State::builder()
            .field("query", "Business value", Type::U64, json!(1))
            .build()
            .unwrap();
        let mut updates = StateUpdates::default();
        updates.set("query".into(), Some(json!(2)));
        updates.set_in(Input, "query".into(), Some(json!("coffee")));
        updates.set("query".into(), None);
        assert!(updates.get("query").is_none());
        assert_eq!(updates.get_in(Input, "query"), Some(&json!("coffee")));
        state.validate_updates(&updates).unwrap();
        state.apply_updates(&updates);
        assert_eq!(state.get("query"), Some(&json!(1)));
        updates.set_in(Input, "query".into(), None);
        assert!(updates.get_in(Input, "query").is_none());
        assert_eq!(state.get("query"), Some(&json!(1)));
    }

    #[test]
    fn nested_declarations_validate_initial_values_and_replacements() {
        let ty = Type::Mapping(Box::new(Type::List(Box::new(Type::String))));
        assert!(
            State::builder()
                .field("record", "", ty.clone(), json!({"names": [1]}))
                .build()
                .is_err()
        );
        let mut state = State::builder()
            .field("record", "", ty.clone(), json!({"names": []}))
            .field("count", "", Type::U64, json!(0))
            .build()
            .unwrap();
        let initial = state.to_json();
        let mut updates = StateUpdates::default();
        updates.set("count".into(), Some(json!(1)));
        updates.set("record".into(), Some(json!({"names": [1]})));
        assert!(state.validate_updates(&updates).is_err());
        assert_eq!(state.to_json(), initial);
        assert_eq!(state.declared_type("record"), Some(&ty));
        assert_eq!(state.declared_type("count"), Some(&Type::U64));
        updates.set("record".into(), Some(json!({"names": ["first"]})));
        state.validate_updates(&updates).unwrap();
        state.apply_updates(&updates);
        assert_eq!(state.declared_type("record"), Some(&ty));
        assert_eq!(state.to_json(), json!({"count":1,"record":{"names":["first"]}}));
    }

    #[test]
    fn dynamic_values_change_without_changing_the_declaration() {
        let mut state = State::builder()
            .field("value", "", Type::Dynamic, json!(1))
            .build()
            .unwrap();
        let saved = state.clone();
        let mut updates = StateUpdates::default();
        for value in [json!("text"), json!(null)] {
            updates.set("value".into(), Some(value.clone()));
            state.validate_updates(&updates).unwrap();
            state.apply_updates(&updates);
            assert_eq!(state.declared_type("value"), Some(&Type::Dynamic));
            assert_eq!(state.get("value"), Some(&value));
        }
        assert_eq!(saved.get("value"), Some(&json!(1)));
        assert_eq!(saved.declared_type("value"), Some(&Type::Dynamic));
    }

    #[test]
    fn rejects_invalid_state_updates() {
        let state = State::builder()
            .field("query", "Business value", Type::String, json!(""))
            .build()
            .unwrap();
        let mut updates = StateUpdates::default();
        updates.set("query".into(), Some(json!(1)));
        assert!(
            matches!(state.validate_updates(&updates), Err(FlowError::Execution(diagnostics))
                if diagnostics.diagnostics[0].context == "State field query" && diagnostics.diagnostics[0].message.contains("expected string"))
        );
        updates.set("query".into(), None);
        updates.set("unknown".into(), Some(json!(1)));
        assert!(
            matches!(state.validate_updates(&updates), Err(FlowError::Execution(diagnostics))
                if diagnostics.diagnostics[0].context == "State field unknown" && diagnostics.diagnostics[0].message == "unknown field")
        );
        assert_eq!(state.to_json(), json!({"query": ""}));
    }

    #[test]
    fn rejects_duplicate_field_declarations() {
        let duplicate = State::builder()
            .field("query", "", Type::U64, json!(0))
            .field("query", "", Type::U64, json!(1))
            .build()
            .err()
            .unwrap();
        assert_eq!(duplicate.to_string(), "State field query: duplicate field");
    }
}
