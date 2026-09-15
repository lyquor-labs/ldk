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
}

impl fmt::Display for StateNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Default => "default",
            Self::Input => "input",
        })
    }
}

/// Framework-owned State backed by deterministically seeded LDK maps.
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
    /// Starts declaring an initial State.
    pub fn builder() -> StateBuilder {
        StateBuilder::default()
    }

    /// Returns one State field's value with its concrete type.
    pub fn get<V: Value>(&self, name: &str) -> Option<&V> {
        let value: &dyn Any = self.fields.get(name)?.value.as_ref();
        value.downcast_ref()
    }

    /// Verifies staged whole-field replacements.
    pub(super) fn validate_updates(&self, updates: &StateUpdates) -> Result<(), String> {
        for (name, value) in &updates.staging {
            let current = self
                .fields
                .get(name)
                .ok_or_else(|| format!("unknown State field {name}"))?;
            if current.value.as_ref().type_id() != value.as_ref().type_id() {
                return Err(format!("State field {name} has the wrong value type"));
            }
        }
        Ok(())
    }

    /// Applies staged replacements after validation.
    pub(super) fn apply_updates(&mut self, updates: &StateUpdates) {
        for (name, value) in &updates.staging {
            self.fields
                .get_mut(name)
                .expect("StateUpdates fields are validated before commit")
                .value = value.clone();
        }
    }
}

/// Builder for a typed initial [`State`].
#[derive(Default)]
pub struct StateBuilder {
    fields: Vec<(String, StateField)>,
}

impl StateBuilder {
    /// Declares one State field.
    pub fn field<V: Value>(mut self, name: impl Into<String>, description: impl Into<String>, value: V) -> Self {
        self.fields.push((
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
        for (name, field) in self.fields {
            if state.fields.insert(name.clone(), field).is_some() {
                return Err(format!("duplicate State field {name}"));
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

/// A list whose elements all have the same State value type.
#[derive(Clone, Deserialize)]
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
#[derive(Clone)]
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
    pub(super) staging: HashMap<String, Box<dyn Value>>,
    /// Ephemeral values are Step-scoped context inserted by the framework. Submitted input is
    /// stored at (`StateNamespace::Input`, [`crate::InputSpec::name`]) and is readable through
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
        let value: &dyn Any = self.staging.get(name)?.as_ref();
        value.downcast_ref()
    }

    /// Returns one Step-scoped value with its concrete type.
    ///
    /// Input is keyed by (`StateNamespace::Input`, [`crate::InputSpec::name`]).
    pub fn get_ephemeral<V: Value>(&self, namespace: StateNamespace, name: &str) -> Option<&V> {
        let value: &dyn Any = self.ephemeral.get(&namespace)?.get(name)?.as_ref();
        value.downcast_ref()
    }

    /// Adds, replaces, or removes one staged replacement.
    ///
    /// A staged replacement must target an existing State field with the same concrete value type
    /// when the Scope validates the finalized transition against its bound Flow.
    ///
    /// Passing `None` removes the staged value. It does not delete an already committed State field.
    pub fn set(&mut self, name: String, value: Option<Box<dyn Value>>) {
        if let Some(value) = value {
            self.staging.insert(name, value);
        } else {
            self.staging.remove(&name);
        }
    }

    pub(super) fn set_ephemeral(&mut self, namespace: StateNamespace, name: String, value: Option<Box<dyn Value>>) {
        if let Some(value) = value {
            self.ephemeral
                .entry(namespace)
                .or_insert_with(new_hashmap)
                .insert(name, value);
        } else if let Some(fields) = self.ephemeral.get_mut(&namespace) {
            fields.remove(&name);
        }
    }

    /// Accumulates committed replacements.
    pub(super) fn merge(&mut self, updates: Self) {
        self.staging.extend(updates.staging);
    }
}
