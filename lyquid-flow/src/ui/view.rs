use serde::Serialize;

use super::{Builder, Node, UiDocument};

/// Explicitly selected result content and navigation. Input controls and submit actions are not permitted.
#[derive(Clone, Serialize)]
pub struct ViewSpec {
    ui: UiDocument,
}

impl ViewSpec {
    /// Uses the same content/layout builder as InputSpec.
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn finish(builder: &Builder, root: Node) -> Result<Self, String> {
        let ui = builder.finish(root)?;
        if ui.components().iter().any(|component| {
            !(matches!(
                component["component"].as_str(),
                Some("Text" | "Column" | "Row" | "Card")
            ) || (component["component"] == "Button" &&
                component["action"]["functionCall"]["call"] == "openUrl" &&
                component["action"].get("event").is_none()))
        }) {
            return Err("result views cannot contain input controls or actions".to_owned());
        }
        Ok(Self { ui })
    }

    pub fn ui(&self) -> &UiDocument {
        &self.ui
    }
}

impl Default for ViewSpec {
    fn default() -> Self {
        let builder = Self::builder();
        Self::finish(&builder, builder.column(Vec::new())).expect("an empty result view is valid")
    }
}

#[cfg(test)]
mod tests {
    use lyquid_test::test;
    use serde_json::json;

    use super::*;
    use crate::InputSpec;

    #[test]
    fn view_rejects_controls() {
        let mut input = InputSpec::builder();
        let field = input.field("field", "Field", false).toggle();
        assert!(ViewSpec::finish(input.ui(), field).is_err());
    }

    #[test]
    fn view_links() {
        let ui = ViewSpec::builder();
        let spec = ViewSpec::finish(&ui, ui.link("Product source", "https://example.com/product")).unwrap();
        let messages = spec.ui().surface("result", None).unwrap();
        assert_eq!(
            messages[1]["updateComponents"]["components"][1]["action"]["functionCall"]["call"],
            "openUrl"
        );
        let ui = ViewSpec::builder();
        assert!(ViewSpec::finish(&ui, ui.link("Invalid", "javascript:alert(1)")).is_err());
        let input = crate::InputSpec::builder();
        assert!(ViewSpec::finish(input.ui(), input.submit("Submit")).is_err());
    }

    #[test]
    fn named_view_data() {
        #[derive(Serialize)]
        struct Product<'a> {
            title: &'a str,
        }
        let ui = ViewSpec::builder();
        ui.data("products", [Product { title: "Mug" }]);
        let spec = ViewSpec::finish(&ui, ui.text("Mug")).unwrap();
        assert_eq!(spec.ui().data()["products"][0]["title"], "Mug");
        for reserved in ["content", "fields"] {
            let ui = ViewSpec::builder();
            ui.data(reserved, json!({}));
            assert!(ViewSpec::finish(&ui, ui.column(vec![])).is_err());
        }
        let ui = ViewSpec::builder();
        ui.data("products", json!([]));
        ui.data("products", json!([]));
        assert!(ViewSpec::finish(&ui, ui.column(vec![])).is_err());
    }

    #[test]
    fn view_data_serialization() {
        let ui = ViewSpec::builder();
        ui.data(
            "products",
            std::collections::BTreeMap::from([(vec![1, 2], "invalid JSON key")]),
        );
        let error = ViewSpec::finish(&ui, ui.text("Products")).err().unwrap();
        assert!(error.contains("UI data products"));
        assert!(error.contains("key must be a string"));
    }
}
