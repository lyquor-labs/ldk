//! The shipped Rust and JSON forms compose with ordinary Step wiring.

use std::sync::Arc;

use lyquid_flow::{AutoCheckpointConfig, Flow, InputSpec, Scope, State, Step, TraceSummary};
use lyquid_test::test;
use serde_json::{Value, json};

use crate::{StructuredStepBuilder, ValueSource};

#[path = "../multiple-choice/input.rs"] mod multiple_choice;
#[path = "../text/input.rs"] mod text;

fn scope(step: impl Step, field: &str) -> Scope {
    Scope::new(
        Arc::new(
            Flow::builder("input-example")
                .entry("input")
                .step("input", step)
                .exit("text_input")
                .exit("done")
                .build()
                .unwrap(),
        ),
        State::builder()
            .field(field, "Submission", "unchanged".to_owned())
            .build()
            .unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    )
}

fn assert_ui(spec: &InputSpec, field: &str, component: &str, prompt: &str, submit: &str) -> Value {
    let ui = serde_json::to_value(spec.ui()).unwrap();
    let components = ui["components"].as_array().unwrap();
    let control = components.iter().find(|node| node["component"] == component).unwrap();
    assert_eq!(control["label"], prompt);
    assert_eq!(control["value"], json!({"path": format!("/fields/{field}")}));
    let button = components.iter().find(|node| node["component"] == "Button").unwrap();
    assert_eq!(button["action"], json!({"event": {"name": "submit", "context": {}}}));
    let label = components.iter().find(|node| node["id"] == button["child"]).unwrap();
    assert_eq!(label["component"], "Text");
    assert_eq!(
        ui["data"].pointer(label["text"]["path"].as_str().unwrap()).unwrap(),
        submit
    );
    let root = components.iter().find(|node| node["id"] == ui["root"]).unwrap();
    assert_eq!(root["component"], "Column");
    // The Rust UI builder wraps the supplied layout in its generated root column.
    let layout = if root["children"].as_array().unwrap().len() == 1 {
        components
            .iter()
            .find(|node| node["id"] == root["children"][0])
            .unwrap()
    } else {
        root
    };
    assert_eq!(layout["component"], "Column");
    assert_eq!(layout["children"], json!([control["id"], button["id"]]));
    control.clone()
}

#[test]
fn text_examples_preserve_exact_submissions_with_direct_state_bindings() {
    let rust = text::input_spec().unwrap();
    let json: InputSpec = serde_json::from_str(include_str!("../text/input.json")).unwrap();
    assert_eq!(rust.schema(), json.schema());
    for input in [rust, json] {
        let control = assert_ui(&input, "message", "TextField", "Your message", "Send");
        assert_eq!(control["variant"], "shortText");
        for message in ["", " \n\t ", "  Keep {{ this }} exactly.\n"] {
            let step = StructuredStepBuilder::new()
                .description("Collect a text message")
                .with_input(input.clone())
                .update_from("message", ValueSource::Input { name: "message".into() })
                .next("done")
                .summary("Received a text message")
                .build()
                .unwrap();
            let mut scope = scope(step, "message");
            scope.run_until_input().unwrap().unwrap();
            let handle = scope.input_handle();
            for invalid in [
                json!({}),
                json!({"message": 42}),
                json!({"message": "ok", "extra": true}),
            ] {
                assert!(handle.submit_input(&invalid.to_string()).is_err());
                assert!(handle.input_spec().is_some());
                assert_eq!(scope.state().get::<String>("message").unwrap(), "unchanged");
                assert!(scope.trace().entries.is_empty());
            }
            handle.submit_input(&json!({"message": message}).to_string()).unwrap();
            scope.advance().unwrap();
            assert_eq!(scope.state().get::<String>("message").unwrap(), message);
            assert_eq!(scope.current_step().0, "done");
            assert!(
                matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Received a text message")
            );
        }
    }
}

#[test]
fn choice_examples_use_ids_as_data_and_consumer_owned_routes() {
    let rust = multiple_choice::input_spec().unwrap();
    let json: InputSpec = serde_json::from_str(include_str!("../multiple-choice/input.json")).unwrap();
    assert_eq!(rust.schema(), json.schema());
    for input in [rust, json] {
        let control = assert_ui(&input, "choice", "ChoicePicker", "What next?", "Choose");
        assert_eq!(control["variant"], "mutuallyExclusive");
        assert_eq!(
            control["options"],
            json!([
                {"label": "Edit the details", "value": "\"edit\""},
                {"label": "Finish", "value": "\"finish\""},
            ])
        );
        for (choice, destination) in [("edit", "text_input"), ("finish", "done")] {
            let step = StructuredStepBuilder::new()
                .description("Choose an action")
                .with_input(input.clone())
                .bind_input("choice", "choice")
                .update_from("choice", ValueSource::Input { name: "choice".into() })
                .route_by("/choice", [("edit", "text_input"), ("finish", "done")])
                .summary("Chose {{ result.choice }}")
                .build()
                .unwrap();
            let mut scope = scope(step, "choice");
            scope.run_until_input().unwrap().unwrap();
            let handle = scope.input_handle();
            for invalid in [
                json!({}),
                json!({"choice": "unknown"}),
                json!({"choice": "Edit the details"}),
                json!({"choice": "text_input"}),
                json!({"choice": 42}),
            ] {
                assert!(handle.submit_input(&invalid.to_string()).is_err());
                assert!(handle.input_spec().is_some());
                assert_eq!(scope.state().get::<String>("choice").unwrap(), "unchanged");
                assert!(scope.trace().entries.is_empty());
            }
            handle.submit_input(&json!({"choice": choice}).to_string()).unwrap();
            scope.advance().unwrap();
            assert_eq!(scope.state().get::<String>("choice").unwrap(), choice);
            assert_eq!(scope.current_step().0, destination);
            assert!(
                matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == &format!("Chose {choice}"))
            );
        }
    }
}
