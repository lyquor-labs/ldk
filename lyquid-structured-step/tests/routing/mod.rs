//! Declared routing and execution-context bindings through the ordinary Scope lifecycle.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use lyquid::prelude::Mutex;
use lyquid_flow::{AutoCheckpointConfig, ExitTransitions, Flow, InputSpec, Scope, State, Step, TraceMode};
use lyquid_test::test;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{NextCase, NextStep, StepWiring, StructuredStepBuilder};

fn scope(step: impl Step) -> Scope {
    Scope::new(
        Arc::new(
            Flow::builder("routes")
                .entry("start")
                .step("start", step)
                .exit("done")
                .build()
                .unwrap(),
        ),
        State::builder().field("value", "Result", 7_u64).build().unwrap(),
        AutoCheckpointConfig::Unbounded,
        None,
    )
}

fn wiring() -> StepWiring {
    StructuredStepBuilder::new()
        .description("Route a result")
        .next("done")
        .update("value", "/value")
        .route_by("/route", [("a", "done"), ("b", "done")])
        .wiring()
        .clone()
}

#[test]
fn all_declared_routes_are_validated_before_the_action() {
    let mut empty = wiring();
    empty.next = NextStep::Result {
        pointer: "/route".into(),
        cases: vec![],
    };
    for wiring in [
        empty,
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .route_by("not-a-pointer", [("a", "done")])
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .route_by("/bad~", [("a", "done")])
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .route_by("/bad~2", [("a", "done")])
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .route_by("/route", [("a", "done"), ("a", "done")])
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .route_by("/route", [("a", "done"), ("b", "missing")])
            .wiring()
            .clone(),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let built = StructuredStepBuilder::operation(move |_: &Value| {
            counted.fetch_add(1, Ordering::Relaxed);
            Ok(json!({"route": "a", "value": 8}))
        })
        .with_wiring(wiring)
        .build();
        let Ok(step) = built else {
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            continue;
        };
        let mut scope = scope(step);
        assert!(scope.advance().is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(scope.state().get::<u64>("value"), Some(&7));
        assert!(scope.trace().entries.is_empty());
    }
}

#[test]
fn unknown_missing_and_non_string_routes_do_not_commit_a_turn() {
    for result in [
        json!({"value": 8}),
        json!({"route": 1, "value": 8}),
        json!({"route": "done", "value": 8}),
        json!({"route": "other", "value": 8}),
    ] {
        let mut scope = scope(
            StructuredStepBuilder::operation(move |_: &Value| Ok(result.clone()))
                .with_wiring(wiring())
                .build()
                .unwrap(),
        );
        let checkpoints = scope.checkpoint_ids().count();
        assert!(scope.advance().is_err());
        assert_eq!(scope.current_step().0, "start");
        assert_eq!(scope.state().get::<u64>("value"), Some(&7));
        assert!(scope.trace().entries.is_empty());
        assert_eq!(scope.checkpoint_ids().count(), checkpoints);
    }
}

#[test]
fn routes_round_trip_and_may_share_a_target_or_complete_the_root() {
    for route in ["a", "b"] {
        let encoded = serde_json::to_string(&wiring()).unwrap();
        let wiring = serde_json::from_str(&encoded).unwrap();
        let mut scope = scope(
            StructuredStepBuilder::operation(move |_: &Value| Ok(json!({"route": route, "value": 8})))
                .with_wiring(wiring)
                .build()
                .unwrap(),
        );
        scope.advance().unwrap();
        assert!(scope.is_finished());
        assert_eq!(scope.current_step().0, "done");
        assert_eq!(scope.state().get::<u64>("value"), Some(&8));
    }
    let mut wiring = wiring();
    wiring.next = NextStep::Result {
        pointer: "/route".into(),
        cases: vec![NextCase {
            value: "finish".into(),
            next: None,
        }],
    };
    let mut scope = scope(
        StructuredStepBuilder::operation(|_: &Value| Ok(json!({"route": "finish", "value": 9})))
            .with_wiring(wiring)
            .build()
            .unwrap(),
    );
    scope.advance().unwrap();
    assert!(scope.is_finished());
    assert_eq!(scope.state().get::<u64>("value"), Some(&9));
}

#[test]
fn routing_uses_json_pointer_escapes_and_the_complete_result() {
    for (pointer, result) in [
        ("", json!("finish")),
        ("/a~1b/~0route", json!({"a/b": {"~route": "finish"}})),
        ("/routes/0", json!({"routes": ["finish"]})),
    ] {
        let mut scope = scope(
            StructuredStepBuilder::operation(move |_: &Value| Ok(result.clone()))
                .description("Route")
                .next("done")
                .route_by(pointer, [("finish", "done")])
                .build()
                .unwrap(),
        );
        scope.advance().unwrap();
        assert!(scope.is_finished());
        assert_eq!(scope.current_step().0, "done");
    }
}

#[derive(Deserialize, Serialize)]
struct Identity {
    id: String,
}

#[test]
fn execution_id_binding_uses_the_actual_mounted_execution() {
    let expected_id = Arc::new(Mutex::new(None));
    let observed_id = expected_id.clone();
    let step = StructuredStepBuilder::operation(|context: &Identity| Ok(context.id.clone()))
        .description("Capture identity")
        .next("done")
        .bind_execution_id("id")
        .update("id", "")
        .with_input_factory(move |scope| {
            assert!(scope.parent().is_some());
            *observed_id.lock() = Some(scope.execution_id().to_string());
            let builder = InputSpec::builder();
            let submit = builder.submit("Continue");
            builder.finish(submit).unwrap()
        })
        .build()
        .unwrap();
    let child = Flow::builder("child")
        .entry("capture")
        .step("capture", step)
        .exit("done")
        .build()
        .unwrap();
    let parent = Flow::builder("parent")
        .entry("child")
        .exit("done")
        .flow(
            "child",
            child,
            ExitTransitions::new().transition("done", "done").unwrap(),
            TraceMode::Expanded,
        )
        .build()
        .unwrap();
    let mut scope = Scope::new(
        Arc::new(parent),
        State::builder()
            .field("id", "Captured execution", String::new())
            .build()
            .unwrap(),
        AutoCheckpointConfig::Unbounded,
        None,
    );
    scope.run_until_input().unwrap().unwrap();
    scope.input_handle().submit_input("{}").unwrap();
    assert!(scope.run_until_input().unwrap().is_none());
    let child_id = scope.state().get::<String>("id").unwrap();
    assert!(!child_id.is_empty());
    // Guest-test entropy is deterministic, so compare against the actual child callback.
    assert_eq!(Some(child_id), expected_id.lock().as_ref());
}
