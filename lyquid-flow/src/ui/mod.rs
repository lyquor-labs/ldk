//! Shared content and layout builders, implemented with native A2UI components.

use std::sync::Arc;

use lyquid::prelude::Mutex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value as JsonValue};

mod a2ui;
mod view;

pub use view::ViewSpec;

/// Opaque UI content shared by input pages and result presentation.
#[derive(Clone, Serialize)]
pub struct UiDocument {
    root: String,
    components: Vec<JsonValue>,
    data: Map<String, JsonValue>,
}

impl<'de> Deserialize<'de> for UiDocument {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Document {
            root: String,
            components: Vec<JsonValue>,
            data: Map<String, JsonValue>,
        }

        let Document { root, components, data } = Document::deserialize(deserializer)?;
        let document = Self { root, components, data };
        a2ui::validate(&document).map_err(serde::de::Error::custom)?;
        Ok(document)
    }
}

impl UiDocument {
    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn components(&self) -> &[JsonValue] {
        &self.components
    }

    pub fn data(&self) -> &Map<String, JsonValue> {
        &self.data
    }
}

/// One field option. Its JSON value is the submitted business value, not a component identifier.
#[derive(Clone, Debug)]
pub(crate) struct Choice {
    pub value: JsonValue,
    pub label: String,
}

#[derive(Default)]
struct BuildState {
    components: Vec<JsonValue>,
    content: Map<String, JsonValue>,
    data: Map<String, JsonValue>,
    errors: Vec<String>,
}

/// Shared builder for content and layouts. Input controls are exposed only by `InputSpecBuilder`.
#[derive(Clone)]
pub struct Builder {
    state: Arc<Mutex<BuildState>>,
}

/// An opaque reference to native content already emitted by a document's builder.
#[derive(Clone)]
pub struct Node {
    id: String,
    owner: Builder,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(BuildState::default())),
        }
    }
}

impl Builder {
    /// Explicitly selects named application data for a custom renderer of this document.
    /// `content` and `fields` are reserved for generated text and input bindings.
    /// Serialization errors are reported by `finish`, together with other document errors.
    pub fn data(&self, name: &str, value: impl Serialize) {
        let value = serde_json::to_value(value);
        let mut state = self.state.lock();
        if matches!(name, "content" | "fields") || state.data.contains_key(name) {
            state.errors.push(format!("duplicate or reserved UI data key {name}"));
        } else {
            match value {
                Ok(value) => {
                    state.data.insert(name.to_owned(), value);
                }
                Err(error) => state.errors.push(format!("UI data {name}: {error}")),
            }
        }
    }

    fn emit(&self, generate: impl FnOnce(&str, &mut BuildState) -> JsonValue) -> Node {
        let mut state = self.state.lock();
        let id = format!("c{}", state.components.len());
        let component = generate(&id, &mut state);
        state.components.push(component);
        Node {
            id,
            owner: self.clone(),
        }
    }

    fn check_children(&self, children: &[Node]) {
        if children
            .iter()
            .any(|child| !Arc::ptr_eq(&self.state, &child.owner.state))
        {
            self.state.lock().errors.push("layout mixes documents".to_owned());
        }
    }

    /// Finishes a content-only document; input specs use the same document builder internally.
    pub fn finish(&self, root: Node) -> Result<UiDocument, String> {
        if !Arc::ptr_eq(&self.state, &root.owner.state) {
            return Err("root belongs to a different document".to_owned());
        }
        let state = self.state.lock();
        if !state.errors.is_empty() {
            return Err(state.errors.join("; "));
        }
        let root_id = "root";
        let mut components = state.components.clone();
        components.push(a2ui::root(root_id, &root.id));
        let mut data = state.data.clone();
        data.insert("content".to_owned(), JsonValue::Object(state.content.clone()));
        let document = UiDocument {
            root: root_id.to_owned(),
            components,
            data,
        };
        drop(state);
        a2ui::validate(&document)?;
        Ok(document)
    }
}
