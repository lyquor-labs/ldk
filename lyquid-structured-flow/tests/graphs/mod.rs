use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use lyquid_flow::{AutoCheckpointConfig, Flow, ModelTemplate, Scope, State};
use lyquid_test::test;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{StructuredFlowBuilder, StructuredStepBuilder};

#[derive(Serialize, Deserialize, JsonSchema)]
struct Counter {
    count: u64,
}

fn state() -> State {
    State::builder()
        .field("count", "Typed counter", 7_u64)
        .field("protected", "Parent-owned data", String::from("keep"))
        .build()
        .unwrap()
}

#[test]
fn opaque_rust_callbacks_execute_but_cannot_be_silently_dropped_from_export() {
    let step = StructuredStepBuilder::operation(|context: &Counter| Ok(context.count + 1))
        .bind_state("count", "count")
        .update("count", "")
        .next("done");
    assert!(step.to_json().unwrap_err().contains("operation"));
    let built = step.clone().build().unwrap();
    assert!(built.to_json().unwrap_err().contains("operation"));
    let flow = StructuredFlowBuilder::new("rust")
        .entry("increment")
        .exit("done")
        .step("increment", step);
    assert!(flow.to_json().unwrap_err().contains("increment"));
    let flow: Flow = flow.build().unwrap();
    let mut scope = Scope::new(flow.into(), state(), AutoCheckpointConfig::Disabled, None);
    scope.advance().unwrap();
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
}

#[test]
fn native_only_steps_validate_model_destinations_before_execution() {
    let steps = [
        (
            "action",
            StructuredStepBuilder::new()
                .action(|_, _| -> Result<Value, String> { panic!("must not run during build") }),
        ),
        (
            "context preparation",
            StructuredStepBuilder::new()
                .with_context(|_: Value| -> Result<Value, String> { panic!("must not run during build") }),
        ),
        (
            "input factory",
            StructuredStepBuilder::new().with_input_factory(|_| panic!("must not run during build")),
        ),
    ];
    for (opaque, step) in steps {
        for (next, field, expected) in [
            ("missing", "count", Some("unknown destination missing")),
            ("done", "count", None),
        ] {
            let step = step
                .clone()
                .with_model(ModelTemplate::new(
                    "Model",
                    vec![(Some(next.into()), "Continue".into())],
                    vec![(field.into(), "Update".into())],
                ))
                .proposed_next();
            assert!(step.to_json().unwrap_err().contains(opaque));
            let flow = StructuredFlowBuilder::new("native-only")
                .entry("model")
                .exit("done")
                .step("model", step);
            if let Some(expected) = expected {
                let error = format!("node \"model\": {expected}");
                assert_eq!(flow.to_json().unwrap_err(), error);
                assert_eq!(flow.build().err().unwrap(), error);
            } else {
                assert!(flow.to_json().unwrap_err().contains(opaque));
                assert!(flow.build().is_ok());
            }
        }
    }
}

fn assert_invalid_model_declaration(model: ModelTemplate, expected: &str) {
    let steps = [
        StructuredStepBuilder::new().action_with_config("unreachable", (), |_, _, &()| -> Result<Value, String> {
            panic!("validation must not execute actions")
        }),
        StructuredStepBuilder::new()
            .action(|_, _| -> Result<Value, String> { panic!("validation must not execute actions") }),
    ];
    for step in steps {
        let step = step.with_model(model.clone());
        for step in [step.clone().proposed_next(), step.next("done")] {
            let flow = StructuredFlowBuilder::new("invalid-model")
                .entry("model")
                .exit("done")
                .step("model", step);
            let expected = format!("node \"model\": {expected}");
            assert_eq!(flow.to_json().unwrap_err(), expected);
            assert_eq!(flow.build().err().unwrap(), expected);
        }
    }
}

#[test]
fn model_declarations_require_a_next_step_criterion() {
    assert_invalid_model_declaration(
        ModelTemplate::new("Model", vec![], vec![]),
        "a model template must declare at least one next-step criterion",
    );
}

#[test]
fn model_declarations_reject_duplicate_step_exit_and_completion_targets() {
    for (target, expected) in [
        (Some("model".into()), "duplicate next-step criterion for Step model"),
        (Some("done".into()), "duplicate next-step criterion for Step done"),
        (None, "duplicate next-step criterion for Flow completion"),
    ] {
        assert_invalid_model_declaration(
            ModelTemplate::new(
                "Model",
                vec![
                    (target.clone(), "First criterion".into()),
                    (target, "Second criterion".into()),
                ],
                vec![],
            ),
            expected,
        );
    }
}

#[test]
fn model_declarations_reject_duplicate_state_update_fields() {
    assert_invalid_model_declaration(
        ModelTemplate::new(
            "Model",
            vec![(Some("done".into()), "Finish".into())],
            vec![
                ("count".into(), "First update".into()),
                ("count".into(), "Second update".into()),
            ],
        ),
        "duplicate State update criterion for field count",
    );
}

#[test]
fn model_declarations_allow_distinct_targets_and_state_fields() {
    let model = ModelTemplate::new(
        "Model",
        vec![
            (Some("model".into()), "Continue".into()),
            (Some("done".into()), "Exit".into()),
            (None, "Complete".into()),
        ],
        vec![
            ("count".into(), "Update count".into()),
            ("protected".into(), "Update text".into()),
        ],
    );
    let flow = StructuredFlowBuilder::new("valid-model")
        .entry("model")
        .exit("done")
        .step("model", StructuredStepBuilder::new().with_model(model).proposed_next());
    assert!(flow.to_json().is_ok());
    assert!(flow.build().is_ok());
}

#[test]
fn step_export_preserves_order_settings_named_results_and_native_execution() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let step = StructuredStepBuilder::new()
        .bind_state("count", "count")
        .action_named_with_config("first", "add", 2_u64, move |context, _, amount| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(context["count"].as_u64().unwrap() + amount)
        })
        .action_with_config("multiply", 3_u64, |context, previous, factor| {
            assert_eq!(context.result("first"), Some(&json!(previous)));
            Ok(previous * factor)
        })
        .update("count", "")
        .next("done");
    let saved = step.to_json().unwrap();
    let definition: lyquid_structured_step::StepConfiguration = serde_json::from_str(&saved).unwrap();
    assert_eq!(definition.to_json().unwrap(), saved);
    let built = step.clone().build().unwrap();
    assert_eq!(built.to_json().unwrap(), saved);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let json: Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(json["finalization"]["actions"][0]["result"], "first");
    assert_eq!(
        json["finalization"]["actions"][1]["callback"],
        json!({"name": "multiply", "settings": 3})
    );
    let flow = StructuredFlowBuilder::new("typed")
        .entry("calculate")
        .exit("done")
        .step("calculate", step);
    let definition: Value = serde_json::from_str(&flow.to_json().unwrap()).unwrap();
    assert_eq!(definition["id"], "typed");
    assert_eq!(definition["entry"], "calculate");
    assert_eq!(definition["exits"], json!(["done"]));
    assert_eq!(definition["nodes"][0]["id"], "calculate");
    assert_eq!(definition["nodes"][0]["component"]["configuration"], json);
    let flow: Flow = flow.build().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut scope = Scope::new(flow.into(), state(), AutoCheckpointConfig::Disabled, None);
    assert_eq!(scope.current_step().0, "calculate");
    scope.advance().unwrap();
    assert_eq!(scope.state().get::<u64>("count"), Some(&27));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(scope.is_finished());
}

#[test]
fn exporting_factories_and_context_preparation_never_calls_them() {
    let step = StructuredStepBuilder::new().with_input_factory(|_| panic!("must not execute during export/build"));
    assert!(step.to_json().unwrap_err().contains("input factory"));
    assert!(step.build().is_ok());
    let step =
        StructuredStepBuilder::new().with_context(|_: Value| -> Result<Value, String> { panic!("must not execute") });
    assert!(step.to_json().unwrap_err().contains("context preparation"));
    assert!(step.build().is_ok());
    let step =
        StructuredStepBuilder::new().with_input_factory_config("input", "settings", |_, _| panic!("must not execute"));
    assert_eq!(
        serde_json::from_str::<Value>(&step.to_json().unwrap()).unwrap()["input"]["callback"],
        json!({"name": "input", "settings": "settings"})
    );
    assert!(step.build().is_ok());
}

#[test]
fn graph_declarations_and_routes_fail_before_actions() {
    let step = StructuredStepBuilder::new()
        .action_with_config("unreachable", (), |_, _, &()| -> Result<Value, String> {
            panic!("build/export must not run actions")
        })
        .next("done");
    let base = StructuredFlowBuilder::new("graph")
        .entry("start")
        .exit("done")
        .step("start", step.clone());
    assert!(base.to_json().is_ok());
    assert!(base.clone().build().is_ok());
    for invalid in [
        base.clone().entry("start"),
        base.clone().exit("done"),
        base.clone().exit("start"),
        base.clone().step("start", step),
        base.clone().step("other", StructuredStepBuilder::new().next("missing")),
        base.clone()
            .step("other", StructuredStepBuilder::new().route_by("", [("go", "missing")])),
        StructuredFlowBuilder::new("no-entry"),
        StructuredFlowBuilder::new("unknown-entry").entry("missing"),
        StructuredFlowBuilder::new(" ")
            .entry("start")
            .step("start", StructuredStepBuilder::new()),
    ] {
        let error = invalid.to_json().unwrap_err();
        assert_eq!(invalid.build().err().unwrap(), error);
    }
    assert!(
        base.step("invalid-template", StructuredStepBuilder::new().summary("{{"))
            .build()
            .is_err()
    );
}
