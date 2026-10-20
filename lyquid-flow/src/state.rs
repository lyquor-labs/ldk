use std::any::Any;
use std::fmt;
use std::marker::PhantomData;

use lyquid::prelude::{HashMap, new_hashmap};
use serde::Deserialize;
use serde::de::{DeserializeOwned, MapAccess, Visitor};

/// Namespace for committed and in-flight State values.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

/// Framework-owned State backed by deterministically seeded LDK maps.
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
    /// Starts declaring an initial State.
    pub fn builder() -> StateBuilder {
        StateBuilder::default()
    }

    /// Returns one State field's value with its concrete type.
    pub fn get<V: Value>(&self, name: &str) -> Option<&V> {
        self.get_in(StateNamespace::Default, name)
    }

    /// Returns one State field from the requested namespace.
    pub fn get_in<V: Value>(&self, namespace: StateNamespace, name: &str) -> Option<&V> {
        let value: &dyn Any = self.get_value_in(namespace, name)?;
        value.downcast_ref()
    }

    /// Reads a committed value and its codec without requiring its concrete type.
    /// Decoding a replacement does not modify State; replacements still require a validated turn.
    pub fn get_value(&self, name: &str) -> Option<&dyn Value> {
        self.get_value_in(StateNamespace::Default, name)
    }

    /// Reads a committed value and its codec from the requested namespace.
    pub fn get_value_in(&self, namespace: StateNamespace, name: &str) -> Option<&dyn Value> {
        self.fields.get(&namespace)?.get(name).map(|field| field.value.as_ref())
    }

    /// Projects committed field values into a JSON object, without descriptions or staged updates.
    /// This read-only view is suitable for templates and does not modify State.
    pub fn to_json(&self) -> Result<serde_json::Value, String> {
        self.to_json_in(StateNamespace::Default)
    }

    /// Projects committed values from the requested namespace.
    pub fn to_json_in(&self, namespace: StateNamespace) -> Result<serde_json::Value, String> {
        self.fields
            .get(&namespace)
            .into_iter()
            .flatten()
            .map(|(name, field)| {
                serde_json::from_str(&field.value.encode())
                    .map(|value| (name.clone(), value))
                    .map_err(|error| format!("invalid JSON for State field {name}: {error}"))
            })
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(serde_json::Value::Object)
    }

    /// Verifies staged whole-field replacements.
    pub(super) fn validate_updates(&self, updates: &StateUpdates) -> Result<(), String> {
        for (namespace, fields) in &updates.staging {
            for (name, value) in fields {
                let current = self
                    .get_value_in(*namespace, name)
                    .ok_or_else(|| format!("unknown State field {namespace}.{name}"))?;
                if current.type_id() != value.as_ref().type_id() {
                    return Err(format!("State field {namespace}.{name} has the wrong value type"));
                }
            }
        }
        Ok(())
    }

    /// Applies staged replacements after validation.
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

/// Builder for a typed initial [`State`].
#[derive(Default)]
pub struct StateBuilder {
    fields: Vec<(StateNamespace, String, StateField)>,
}

impl StateBuilder {
    /// Declares one State field.
    pub fn field<V: Value>(self, name: impl Into<String>, description: impl Into<String>, value: V) -> Self {
        self.field_in(StateNamespace::Default, name, description, value)
    }

    /// Declares one State field in the requested namespace.
    pub fn field_in<V: Value>(
        mut self, namespace: StateNamespace, name: impl Into<String>, description: impl Into<String>, value: V,
    ) -> Self {
        self.fields.push((
            namespace,
            name.into(),
            StateField {
                description: description.into(),
                value: Box::new(value),
            },
        ));
        self
    }

    /// Rejects duplicate declarations and creates the initial State.
    pub fn build(self) -> Result<State, String> {
        let mut state = State::default();
        for (namespace, name, field) in self.fields {
            if namespace == StateNamespace::Input {
                return Err("Input fields are ephemeral and cannot be declared in State".to_owned());
            }
            if state
                .fields
                .entry(namespace)
                .or_insert_with(new_hashmap)
                .insert(name.clone(), field)
                .is_some()
            {
                return Err(format!("duplicate State field {namespace}.{name}"));
            }
        }
        Ok(state)
    }
}

#[derive(Clone)]
pub(super) struct StateField {
    pub(super) description: String,
    pub(super) value: Box<dyn Value>,
}

/// A value that can be stored in [`State`]. The `Any` bound lets State recover its concrete type
/// for typed reads through [`State::get`].
pub trait Value: Any + Send + Sync {
    /// Encodes the current value for templates and model context.
    fn encode(&self) -> String;

    /// Decodes and validates a replacement while preserving this field's type.
    fn decode(&self, model_output: &str) -> Result<Box<dyn Value>, String>;

    /// Clones this value through a trait object.
    fn clone_box(&self) -> Box<dyn Value>;
}

impl Clone for Box<dyn Value> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

macro_rules! impl_value {
    ($type:ty) => {
        impl Value for $type {
            fn encode(&self) -> String {
                serde_json::to_string(self).expect("primitive Value serialization cannot fail")
            }

            fn decode(&self, model_output: &str) -> Result<Box<dyn Value>, String> {
                serde_json::from_str::<Self>(model_output)
                    .map(|value| Box::new(value) as Box<dyn Value>)
                    .map_err(|error| error.to_string())
            }

            fn clone_box(&self) -> Box<dyn Value> {
                Box::new(self.clone())
            }
        }
    };
}

impl_value!(bool);
impl_value!(i64);
impl_value!(u64);
impl_value!(String);
impl_value!(serde_json::Value);

/// A list whose elements all have the same State value type.
#[derive(Clone, Deserialize, schemars::JsonSchema)]
pub struct List<T>(pub Vec<T>);

impl<T> Value for List<T>
where
    T: Clone + DeserializeOwned + Value,
{
    fn encode(&self) -> String {
        let values = self.0.iter().map(Value::encode).collect::<Vec<_>>();
        format!("[{}]", values.join(","))
    }

    fn decode(&self, model_output: &str) -> Result<Box<dyn Value>, String> {
        serde_json::from_str::<Self>(model_output)
            .map(|value| Box::new(value) as Box<dyn Value>)
            .map_err(|error| error.to_string())
    }

    fn clone_box(&self) -> Box<dyn Value> {
        Box::new(self.clone())
    }
}

/// A string-keyed map whose values all have the same State value type.
#[derive(Clone, schemars::JsonSchema)]
#[schemars(with = "std::collections::BTreeMap<String, T>")]
pub struct Mapping<T>(pub HashMap<String, T>);

// Deserialize through `new_hashmap()` so decoded mappings retain the runtime's deterministically seeded hasher.
impl<'de, T> Deserialize<'de> for Mapping<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MappingVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for MappingVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = Mapping<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string-keyed map")
            }

            fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = new_hashmap();
                while let Some((key, value)) = entries.next_entry()? {
                    values.insert(key, value);
                }
                Ok(Mapping(values))
            }
        }

        deserializer.deserialize_map(MappingVisitor(PhantomData))
    }
}

impl<T> Value for Mapping<T>
where
    T: Clone + DeserializeOwned + Value,
{
    fn encode(&self) -> String {
        let fields = self
            .0
            .iter()
            .map(|(key, value)| {
                let key: String = serde_json::to_string(key).expect("String serialization cannot fail");
                format!("{key}:{}", value.encode())
            })
            .collect::<Vec<_>>();
        format!("{{{}}}", fields.join(","))
    }

    fn decode(&self, model_output: &str) -> Result<Box<dyn Value>, String> {
        serde_json::from_str::<Self>(model_output)
            .map(|value| Box::new(value) as Box<dyn Value>)
            .map_err(|error| error.to_string())
    }

    fn clone_box(&self) -> Box<dyn Value> {
        Box::new(self.clone())
    }
}

/// Values available to [`crate::Step::finalize`] during one transition.
#[derive(Clone)]
pub struct StateUpdates {
    /// Staging values are proposed committed State replacements. They come from the model or a
    /// [`crate::TurnProposal::Advance`] decision and may be revised with [`StateUpdates::set`]. Only
    /// staging data is applied when the transition commits.
    pub(super) staging: HashMap<StateNamespace, HashMap<String, Box<dyn Value>>>,
    /// Ephemeral values are Step-scoped context inserted by the framework. Submitted input is
    /// stored at (`StateNamespace::Input`, the declared field key) and is readable through
    /// [`StateUpdates::get_ephemeral`]. Ephemeral values are discarded at commit. To persist one,
    /// clone its typed value and pass it to [`StateUpdates::set`].
    pub(super) ephemeral: HashMap<StateNamespace, HashMap<String, Box<dyn Value>>>,
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
    /// Returns one staged value with its concrete type.
    pub fn get<V: Value>(&self, name: &str) -> Option<&V> {
        self.get_in(StateNamespace::Default, name)
    }

    /// Returns one staged or ephemeral value from the requested namespace.
    pub fn get_in<V: Value>(&self, namespace: StateNamespace, name: &str) -> Option<&V> {
        let value: &dyn Any = self.get_value_in(namespace, name)?;
        value.downcast_ref()
    }

    /// Returns one ephemeral value with its concrete type.
    pub fn get_ephemeral<V: Value>(&self, namespace: StateNamespace, name: &str) -> Option<&V> {
        let value: &dyn Any = self.ephemeral.get(&namespace)?.get(name)?.as_ref();
        value.downcast_ref()
    }

    /// Reads a staged or ephemeral value without requiring its concrete type.
    pub fn get_value_in(&self, namespace: StateNamespace, name: &str) -> Option<&dyn Value> {
        let values = match namespace {
            StateNamespace::Default | StateNamespace::Tool => &self.staging,
            StateNamespace::Input => &self.ephemeral,
        };
        values.get(&namespace)?.get(name).map(Box::as_ref)
    }

    /// Adds, replaces, or removes one staged replacement in the default namespace.
    ///
    /// A staged replacement must target an existing State field with the same concrete value type
    /// when the Scope validates the finalized transition against its bound Flow.
    ///
    /// Passing `None` removes the staged value. It does not delete an already committed State field.
    pub fn set(&mut self, name: String, value: Option<Box<dyn Value>>) {
        self.set_in(StateNamespace::Default, name, value);
    }

    /// Stages a replacement in the requested namespace, or sets an ephemeral Input value.
    pub fn set_in(&mut self, namespace: StateNamespace, name: String, value: Option<Box<dyn Value>>) {
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

    /// Accumulates committed replacements.
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
            .field("query", "Business value", 1_u64)
            .field_in(Tool, "query", "Tool parameter", String::new())
            .build()
            .unwrap();
        let mut updates = StateUpdates::default();
        updates.set("query".into(), Some(Box::new(2_u64)));
        updates.set_in(Tool, "query".into(), Some(Box::new("coffee".to_owned())));
        updates.set_in(Input, "query".into(), Some(Box::new(true)));
        assert_eq!(updates.get_ephemeral::<bool>(Input, "query"), Some(&true));
        assert!(updates.get_ephemeral::<String>(Tool, "query").is_none());
        state.validate_updates(&updates).unwrap();
        state.apply_updates(&updates);
        assert_eq!(state.get::<u64>("query"), Some(&2));
        assert_eq!(state.get_in::<String>(Tool, "query").unwrap(), "coffee");
        assert!(state.get_in::<bool>(Input, "query").is_none());
        assert_eq!(state.to_json().unwrap(), json!({"query": 2}));
        assert_eq!(state.to_json_in(Tool).unwrap(), json!({"query": "coffee"}));
    }

    #[test]
    fn merges_updates_without_cross_namespace_overwrites() {
        let mut updates = StateUpdates::default();
        updates.set("query".into(), Some(Box::new(7_u64)));
        updates.set_in(Tool, "query".into(), Some(Box::new("old".to_owned())));
        updates.set_in(Tool, "limit".into(), Some(Box::new(3_u64)));
        let mut later = StateUpdates::default();
        later.set_in(Tool, "query".into(), Some(Box::new("new".to_owned())));
        later.set_in(Input, "query".into(), Some(Box::new(true)));
        updates.merge(later);
        assert_eq!(updates.get_in::<String>(Tool, "query").unwrap(), "new");
        assert_eq!(updates.get_in::<u64>(Tool, "limit"), Some(&3));
        assert_eq!(updates.get::<u64>("query"), Some(&7));
        assert!(updates.get_in::<bool>(Input, "query").is_none());
        updates.set_in(Tool, "query".into(), None);
        assert!(updates.get_in::<String>(Tool, "query").is_none());
        assert_eq!(updates.get::<u64>("query"), Some(&7));
    }

    #[test]
    fn rejects_invalid_state_updates() {
        let state = State::builder()
            .field("query", "Business value", 0_u64)
            .field_in(Tool, "query", "Tool parameter", String::new())
            .build()
            .unwrap();
        let mut updates = StateUpdates::default();
        updates.set_in(Tool, "query".into(), Some(Box::new(1_u64)));
        assert!(
            state
                .validate_updates(&updates)
                .unwrap_err()
                .contains("wrong value type")
        );
        updates.set_in(Tool, "query".into(), None);
        updates.set_in(Tool, "unknown".into(), Some(Box::new(1_u64)));
        assert!(
            state
                .validate_updates(&updates)
                .unwrap_err()
                .contains("unknown State field")
        );
    }

    #[test]
    fn rejects_invalid_field_declarations() {
        assert!(
            State::builder()
                .field_in(Tool, "query", "", 0_u64)
                .field_in(Tool, "query", "", 1_u64)
                .build()
                .is_err()
        );
        assert!(State::builder().field_in(Input, "query", "", 0_u64).build().is_err());
    }
}
