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
    /// Persistent tool data, separate from ordinary workflow State.
    Tool,
}

impl fmt::Display for StateNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Default => "default",
            Self::Input => "input",
            Self::Tool => "tool",
        })
    }
}

/// Framework-owned JSON State with immutable structural declarations.
#[derive(Clone)]
pub struct State {
    pub(super) fields: HashMap<StateNamespace, HashMap<String, StateField>>,
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
        self.get_in(StateNamespace::Default, name)
    }

    pub fn get_in(&self, namespace: StateNamespace, name: &str) -> Option<&Value> {
        self.fields.get(&namespace)?.get(name).map(|field| &field.value)
    }

    pub fn declared_type(&self, name: &str) -> Option<&Type> {
        self.declared_type_in(StateNamespace::Default, name)
    }

    pub fn declared_type_in(&self, namespace: StateNamespace, name: &str) -> Option<&Type> {
        self.fields.get(&namespace)?.get(name).map(|field| &field.declared_type)
    }

    /// Projects committed values into a JSON object, without declarations or staged updates.
    pub fn to_json(&self) -> Value {
        self.to_json_in(StateNamespace::Default)
    }

    pub fn to_json_in(&self, namespace: StateNamespace) -> Value {
        self.fields
            .get(&namespace)
            .into_iter()
            .flatten()
            .map(|(name, field)| (name.clone(), field.value.clone()))
            .collect::<serde_json::Map<_, _>>()
            .into()
    }

    /// Checks every finalized replacement before any part of the turn is committed.
    pub(super) fn validate_updates(&self, updates: &StateUpdates) -> Result<(), FlowError> {
        for (namespace, fields) in &updates.staging {
            for (name, value) in fields {
                let context = format!("State field {namespace}.{name}");
                let declaration = self
                    .declared_type_in(*namespace, name)
                    .ok_or_else(|| Diagnostic::new(&context, "unknown field"))?;
                declaration
                    .validate(value)
                    .map_err(|error| Diagnostic::with_source(context, error))?;
            }
        }
        Ok(())
    }

    pub(super) fn apply_updates(&mut self, updates: &StateUpdates) {
        for (namespace, fields) in &updates.staging {
            for (name, value) in fields {
                self.fields
                    .get_mut(namespace)
                    .and_then(|fields| fields.get_mut(name))
                    .expect("StateUpdates fields are validated before commit")
                    .value = value.clone();
            }
        }
    }
}

/// Declares each State field's allowed type and initial JSON value explicitly.
#[derive(Default)]
pub struct StateBuilder {
    fields: Vec<(StateNamespace, String, StateField)>,
}

impl StateBuilder {
    pub fn field(self, name: impl Into<String>, description: impl Into<String>, ty: Type, value: Value) -> Self {
        self.field_in(StateNamespace::Default, name, description, ty, value)
    }

    pub fn field_in(
        mut self, namespace: StateNamespace, name: impl Into<String>, description: impl Into<String>, ty: Type,
        value: Value,
    ) -> Self {
        self.fields.push((
            namespace,
            name.into(),
            StateField {
                description: description.into(),
                declared_type: ty,
                value,
            },
        ));
        self
    }

    /// Rejects invalid initial values, duplicate declarations and persistent Input fields.
    pub fn build(self) -> Result<State, BuildError> {
        let mut state = State::default();
        for (namespace, name, field) in self.fields {
            let context = format!("State field {namespace}.{name}");
            if namespace == StateNamespace::Input {
                return Err(
                    Diagnostic::new(context, "Input fields are ephemeral and cannot be declared in State").into(),
                );
            }
            field
                .declared_type
                .validate(&field.value)
                .map_err(|error| Diagnostic::with_source(&context, error))?;
            if state
                .fields
                .entry(namespace)
                .or_insert_with(new_hashmap)
                .insert(name, field)
                .is_some()
            {
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
    pub(super) staging: HashMap<StateNamespace, HashMap<String, Value>>,
    pub(super) ephemeral: HashMap<StateNamespace, HashMap<String, Value>>,
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
            StateNamespace::Default | StateNamespace::Tool => &self.staging,
            StateNamespace::Input => &self.ephemeral,
        };
        values.get(&namespace)?.get(name)
    }

    /// Stages a replacement; None removes the proposal, not the committed field.
    pub fn set(&mut self, name: String, value: Option<Value>) {
        self.set_in(StateNamespace::Default, name, value);
    }

    /// Staged values are checked at the Flow commit boundary. Input values are never committed.
    pub fn set_in(&mut self, namespace: StateNamespace, name: String, value: Option<Value>) {
        let values = match namespace {
            StateNamespace::Default | StateNamespace::Tool => &mut self.staging,
            StateNamespace::Input => &mut self.ephemeral,
        };
        if let Some(value) = value {
            values.entry(namespace).or_insert_with(new_hashmap).insert(name, value);
        } else if let Some(fields) = values.get_mut(&namespace) {
            fields.remove(&name);
        }
    }

    pub(super) fn merge(&mut self, updates: Self) {
        for (namespace, fields) in updates.staging {
            self.staging.entry(namespace).or_insert_with(new_hashmap).extend(fields);
        }
    }
}

#[cfg(test)]
mod tests {
    use lyquid_test::test;
    use serde_json::json;

    use super::*;
    use StateNamespace::{Input, Tool};

    #[test]
    fn commits_same_named_fields_in_separate_namespaces() {
        let mut state = State::builder()
            .field("query", "Business value", crate::Type::U64, serde_json::json!(1_u64))
            .field_in(
                Tool,
                "query",
                "Tool parameter",
                crate::Type::String,
                serde_json::json!(""),
            )
            .build()
            .unwrap();
        let mut updates = StateUpdates::default();
        updates.set("query".into(), Some(serde_json::json!(2_u64)));
        updates.set_in(Tool, "query".into(), Some(serde_json::json!("coffee")));
        updates.set_in(Input, "query".into(), Some(serde_json::json!(true)));
        assert_eq!(updates.get_in(Input, "query"), Some(&json!(true)));
        assert_eq!(updates.get_in(Tool, "query"), Some(&json!("coffee")));
        state.validate_updates(&updates).unwrap();
        state.apply_updates(&updates);
        assert_eq!(state.get("query").and_then(serde_json::Value::as_u64), Some(2));
        assert_eq!(
            state.get_in(Tool, "query").and_then(serde_json::Value::as_str).unwrap(),
            "coffee"
        );
        assert!(
            state
                .get_in(Input, "query")
                .and_then(serde_json::Value::as_bool)
                .is_none()
        );
        assert_eq!(state.to_json(), json!({"query": 2}));
        assert_eq!(state.to_json_in(Tool), json!({"query": "coffee"}));
    }

    #[test]
    fn merges_updates_without_cross_namespace_overwrites() {
        let mut updates = StateUpdates::default();
        updates.set("query".into(), Some(serde_json::json!(7_u64)));
        updates.set_in(Tool, "query".into(), Some(serde_json::json!("old")));
        updates.set_in(Tool, "limit".into(), Some(serde_json::json!(3_u64)));
        let mut later = StateUpdates::default();
        later.set_in(Tool, "query".into(), Some(serde_json::json!("new")));
        later.set_in(Input, "query".into(), Some(serde_json::json!(true)));
        updates.merge(later);
        assert_eq!(
            updates
                .get_in(Tool, "query")
                .and_then(serde_json::Value::as_str)
                .unwrap(),
            "new"
        );
        assert_eq!(
            updates.get_in(Tool, "limit").and_then(serde_json::Value::as_u64),
            Some(3)
        );
        assert_eq!(updates.get("query").and_then(serde_json::Value::as_u64), Some(7));
        assert!(
            updates
                .get_in(Input, "query")
                .and_then(serde_json::Value::as_bool)
                .is_none()
        );
        updates.set_in(Tool, "query".into(), None);
        assert!(
            updates
                .get_in(Tool, "query")
                .and_then(serde_json::Value::as_str)
                .is_none()
        );
        assert_eq!(updates.get("query").and_then(serde_json::Value::as_u64), Some(7));
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
            .field("query", "Business value", crate::Type::U64, serde_json::json!(0_u64))
            .field_in(
                Tool,
                "query",
                "Tool parameter",
                crate::Type::String,
                serde_json::json!(""),
            )
            .build()
            .unwrap();
        let mut updates = StateUpdates::default();
        updates.set_in(Tool, "query".into(), Some(serde_json::json!(1_u64)));
        assert!(
            matches!(state.validate_updates(&updates), Err(FlowError::Execution(diagnostics))
                if diagnostics.diagnostics[0].context == "State field tool.query" && diagnostics.diagnostics[0].message.contains("expected string"))
        );
        updates.set_in(Tool, "query".into(), None);
        updates.set_in(Tool, "unknown".into(), Some(serde_json::json!(1_u64)));
        assert!(
            matches!(state.validate_updates(&updates), Err(FlowError::Execution(diagnostics))
                if diagnostics.diagnostics[0].context == "State field tool.unknown" && diagnostics.diagnostics[0].message == "unknown field")
        );
    }

    #[test]
    fn rejects_invalid_field_declarations() {
        let duplicate = State::builder()
            .field_in(Tool, "query", "", crate::Type::U64, serde_json::json!(0_u64))
            .field_in(Tool, "query", "", crate::Type::U64, serde_json::json!(1_u64))
            .build()
            .err()
            .unwrap();
        assert_eq!(duplicate.to_string(), "State field tool.query: duplicate field");
        let ephemeral = State::builder()
            .field_in(Input, "query", "", crate::Type::U64, serde_json::json!(0_u64))
            .build()
            .err()
            .unwrap();
        assert_eq!(
            ephemeral.to_string(),
            "State field input.query: Input fields are ephemeral and cannot be declared in State"
        );
    }
}
