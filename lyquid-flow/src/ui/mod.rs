//! Shared content and layout builders, implemented with native A2UI components.

use std::sync::Arc;

use lyquid::prelude::Mutex;
use serde::Serialize;
use serde_json::{Map, Value as JsonValue};

mod a2ui;

/// Opaque UI content shared by input pages and result presentation.
#[derive(Clone, Serialize)]
pub struct UiDocument {
    root: String,
    components: Vec<JsonValue>,
    data: Map<String, JsonValue>,
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
        let document = UiDocument {
            root: root_id.to_owned(),
            components,
            data: Map::from_iter([("content".to_owned(), JsonValue::Object(state.content.clone()))]),
        };
        drop(state);
        a2ui::validate(&document)?;
        Ok(document)
    }
}
