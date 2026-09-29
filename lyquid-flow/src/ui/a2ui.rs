//! Native A2UI v0.9.1 basic-catalog builders and document validation.
//!
//! Surface messages, input-round event binding, and frontend adapters belong to the transport layer.

use serde_json::{Value as JsonValue, json};

use super::{Builder, Choice, Node, UiDocument};

pub(super) fn root(id: &str, child: &str) -> JsonValue {
    json!({"id": id, "component": "Column", "children": [child]})
}

pub(super) fn validate(document: &UiDocument) -> Result<(), String> {
    let mut ids = std::collections::BTreeSet::new();
    for component in &document.components {
        let id = component["id"].as_str().ok_or("component has no ID")?;
        if !ids.insert(id) {
            return Err(format!("duplicate component ID {id}"));
        }
        if !matches!(
            component["component"].as_str(),
            Some("Text" | "Column" | "Row" | "Card" | "TextField" | "CheckBox" | "ChoicePicker" | "Button")
        ) {
            return Err("component is not in the supported catalog".to_owned());
        }
    }
    if !ids.contains(document.root.as_str()) {
        return Err("the UI root is missing".to_owned());
    }
    for component in &document.components {
        let children = component["children"].as_array().into_iter().flatten();
        for child in children.chain(component.get("child")) {
            if !child.as_str().is_some_and(|child| ids.contains(child)) {
                return Err("component references an unknown child".to_owned());
            }
        }
    }
    Ok(())
}

impl Builder {
    /// Selects one value for presentation and creates its binding; no State is exported implicitly.
    pub fn text(&self, text: impl Into<String>) -> Node {
        self.emit(|id, state| {
            state.content.insert(id.to_owned(), text.into().into());
            json!({"id": id, "component": "Text", "text": {"path": format!("/content/{id}")}})
        })
    }

    /// Arranges this builder's nodes vertically, including an empty list of children.
    pub fn column(&self, children: Vec<Node>) -> Node {
        self.check_children(&children);
        let children = children.into_iter().map(|child| child.id).collect::<Vec<_>>();
        self.emit(|id, _| json!({"id": id, "component": "Column", "children": children}))
    }

    /// Arranges this builder's nodes horizontally, including an empty list of children.
    pub fn row(&self, children: Vec<Node>) -> Node {
        self.check_children(&children);
        let children = children.into_iter().map(|child| child.id).collect::<Vec<_>>();
        self.emit(|id, _| json!({"id": id, "component": "Row", "children": children}))
    }

    pub fn card(&self, child: Node) -> Node {
        self.check_children(std::slice::from_ref(&child));
        self.emit(|id, _| json!({"id": id, "component": "Card", "child": child.id}))
    }

    pub(crate) fn text_input(&self, field: &str, label: &str) -> Node {
        self.text_field(field, label, "shortText")
    }

    pub(crate) fn text_area(&self, field: &str, label: &str) -> Node {
        self.text_field(field, label, "longText")
    }

    pub(crate) fn number_input(&self, field: &str, label: &str) -> Node {
        self.text_field(field, label, "number")
    }

    pub(crate) fn json_input(&self, field: &str, label: &str) -> Node {
        self.text_field(field, label, "longText")
    }

    fn text_field(&self, field: &str, label: &str, variant: &str) -> Node {
        let path = format!("/fields/{}", crate::input::escape_pointer(field));
        self.emit(|id, _| {
            json!({
                "id": id, "component": "TextField", "label": label, "value": {"path": path},
                "variant": variant,
            })
        })
    }

    pub(crate) fn toggle(&self, field: &str, label: &str) -> Node {
        let path = format!("/fields/{}", crate::input::escape_pointer(field));
        self.emit(|id, _| json!({"id": id, "component": "CheckBox", "label": label, "value": {"path": path}}))
    }

    pub(crate) fn select_one(&self, field: &str, label: &str, choices: &[Choice]) -> Node {
        self.choice_picker(field, label, choices, "mutuallyExclusive")
    }

    pub(crate) fn select_many(&self, field: &str, label: &str, choices: &[Choice]) -> Node {
        self.choice_picker(field, label, choices, "multipleSelection")
    }

    // Encode JSON inside each native option string to preserve distinctions such as true vs "true".
    // Frontend adapters must decode selected options into scalar or list values matching the field schema.
    fn choice_picker(&self, field: &str, label: &str, choices: &[Choice], variant: &str) -> Node {
        let path = format!("/fields/{}", crate::input::escape_pointer(field));
        self.emit(|id, _| {
            json!({
                "id": id, "component": "ChoicePicker", "label": label, "value": {"path": path},
                "options": choices.iter().map(|choice| json!({
                    "label": choice.label,
                    "value": choice.value.to_string(),
                })).collect::<Vec<_>>(),
                "variant": variant,
            })
        })
    }

    pub(crate) fn submit(&self, label: &str) -> Node {
        let text = self.text(label);
        self.emit(
            |id, _| json!({"id": id, "component": "Button", "child": text.id, "action": {"event": {"name": "submit"}}}),
        )
    }
}
