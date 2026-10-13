//! Native A2UI v0.9.1 basic-catalog builders and document validation.
//!
//! The client service packages these documents into separate input and result surfaces.

use serde_json::{Value as JsonValue, json};

use super::{Builder, Choice, Node, UiDocument};

impl UiDocument {
    /// A complete A2UI v0.9.1 surface snapshot. Recreate an existing surface before replaying it.
    /// Only an input surface may supply a request ID; submit events capture it as a literal.
    pub(crate) fn surface(&self, surface_id: &str, request_id: Option<&str>) -> Result<Vec<JsonValue>, String> {
        validate(self)?;
        let mut components = self.components.clone();
        for component in &mut components {
            if component["component"] == "Button" && component["action"].get("event").is_some() {
                let request_id = request_id.ok_or("result surfaces cannot submit input")?;
                component["action"]["event"]["context"]["request_id"] = json!(request_id);
            }
        }
        Ok(vec![
            json!({"version": "v0.9.1", "createSurface": {
                "surfaceId": surface_id,
                "catalogId": "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json",
            }}),
            json!({"version": "v0.9.1", "updateComponents": {"surfaceId": surface_id, "components": components}}),
            json!({"version": "v0.9.1", "updateDataModel": {"surfaceId": surface_id, "path": "/", "value": self.data}}),
        ])
    }
}

pub(super) fn root(id: &str, child: &str) -> JsonValue {
    json!({"id": id, "component": "Column", "children": [child]})
}

pub(super) fn validate(document: &UiDocument) -> Result<(), String> {
    let mut ids = std::collections::BTreeMap::new();
    for (index, component) in document.components.iter().enumerate() {
        let id = component["id"].as_str().ok_or("component has no ID")?;
        if ids.insert(id, index).is_some() {
            return Err(format!("duplicate component ID {id}"));
        }
        match component["component"].as_str() {
            Some("Column" | "Row") => {
                if !component["children"].is_array() {
                    return Err("Column and Row require an array of child IDs".to_owned());
                }
            }
            Some("Card" | "Button") => {
                if !component["child"].is_string() {
                    return Err("Card and Button require a child ID string".to_owned());
                }
            }
            Some("Text" | "TextField" | "CheckBox" | "ChoicePicker") => (),
            _ => return Err("component is not in the supported catalog".to_owned()),
        }
        if component["component"] == "Button" {
            validate_button_action(&component["action"])?;
        }
    }
    if document.root != "root" {
        return Err("the UI root ID must be \"root\"".to_owned());
    }
    if !ids.contains_key(document.root.as_str()) {
        return Err("the UI root is missing".to_owned());
    }
    let mut edges = vec![Vec::new(); document.components.len()];
    let mut incoming = vec![0usize; document.components.len()];
    for (index, component) in document.components.iter().enumerate() {
        let children = component["children"].as_array().into_iter().flatten();
        for child in children.chain(component.get("child")) {
            let &child = child
                .as_str()
                .and_then(|child| ids.get(child))
                .ok_or("component references an unknown child")?;
            edges[index].push(child);
            incoming[child] += 1;
        }
    }
    // Remove components in topological order. Shared children are valid, but cycles anywhere
    // in the document leave components behind. Use iteration rather than recursing over JSON input.
    let mut pending = incoming
        .iter()
        .enumerate()
        .filter_map(|(index, &count)| (count == 0).then_some(index))
        .collect::<Vec<_>>();
    let mut visited = 0;
    while let Some(index) = pending.pop() {
        visited += 1;
        for &child in &edges[index] {
            incoming[child] -= 1;
            if incoming[child] == 0 {
                pending.push(child);
            }
        }
    }
    if visited != document.components.len() {
        return Err("cyclic UI component references".to_owned());
    }
    Ok(())
}

fn validate_button_action(action: &JsonValue) -> Result<(), String> {
    let action = action.as_object().ok_or("Button actions require an object")?;
    match (action.get("event"), action.get("functionCall")) {
        (Some(event), None) => {
            if event.get("name").and_then(JsonValue::as_str) != Some("submit") {
                return Err("Button events require the name \"submit\"".to_owned());
            }
            if !event.get("context").is_some_and(JsonValue::is_object) {
                return Err("submit events require an object context".to_owned());
            }
        }
        (None, Some(call)) => {
            if call.get("call").and_then(JsonValue::as_str) != Some("openUrl") {
                return Err("Button function calls must use openUrl".to_owned());
            }
            let url = call.get("args").and_then(|args| args.get("url"));
            if !url.is_some_and(|url| url.is_string() || url.get("path").is_some_and(JsonValue::is_string)) {
                return Err("openUrl requires a URL string or data path".to_owned());
            }
        }
        _ => return Err("Button actions require exactly one event or functionCall".to_owned()),
    }
    Ok(())
}

impl Builder {
    /// A native heading; the content uses A2UI's simple Markdown text rules.
    pub fn heading(&self, text: impl Into<String>) -> Node {
        self.emit(|id, state| {
            state.content.insert(id.to_owned(), text.into().into());
            json!({"id": id, "component": "Text", "variant": "h2", "text": {"path": format!("/content/{id}")}})
        })
    }

    /// A native openUrl action. Result views permit navigation, never input submission.
    pub fn link(&self, label: impl Into<String>, url: impl Into<String>) -> Node {
        let url = url.into();
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            self.state
                .lock()
                .errors
                .push("UI links require an HTTP(S) URL".to_owned());
        }
        let text = self.text(label);
        self.emit(|id, _| {
            json!({
                "id": id, "component": "Button", "child": text.id, "variant": "borderless",
                "action": {"functionCall": {"call": "openUrl", "args": {"url": url}, "returnType": "void"}},
            })
        })
    }

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
    // Frontend adapters decode selected options before normalizing scalar versus list selection.
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

    pub(crate) fn submit(&self, label: &str, values: serde_json::Map<String, JsonValue>) -> Node {
        let text = self.text(label);
        self.emit(|id, state| {
            let mut context = json!({});
            if !values.is_empty() {
                state.content.insert(id.to_owned(), values.into());
                context["values"] = json!({"path": format!("/content/{id}")});
            }
            json!({"id": id, "component": "Button", "child": text.id,
                "action": {"event": {"name": "submit", "context": context}}})
        })
    }
}
