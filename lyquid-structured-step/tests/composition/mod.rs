use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lyquid_llm::{
    Backend, JsonApiResponse, LlmError, LlmResult, ModelConfig, ModelRequest, ModelResponse, PreparedJsonApiRequest,
};
use lyquid_test::test;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::{BindingTarget, StepWiring, StructuredStepBuilder, ValueSource};
use lyquid_flow::{
    AutoCheckpointConfig, ExitTransitions, Flow, FlowError, InputSpec, ModelTemplate, Scope, State, StateNamespace,
    StateUpdates, Step, TemplateSpec, TraceMode, TraceSummary, TurnProposal, Value,
};

#[derive(Serialize, Deserialize)]
struct CounterContext {
    count: u64,
}

fn wiring() -> StepWiring {
    StructuredStepBuilder::new()
        .description("Increment a counter")
        .next("done")
        .bind_state("count", "count")
        .update("count", "/count")
        .constant("message", "")
        .summary("Count {{ context.count }} -> {{ result.count }}")
        .wiring()
        .clone()
}

fn state() -> State {
    State::builder()
        .field("count", "Counter", 7_u64)
        .field("message", "Message", String::from("previous"))
        .field("protected", "Application-owned data", 99_u64)
        .build()
        .unwrap()
}

fn scope(step: impl Step) -> Scope {
    scope_with_model(step, None)
}

fn scope_with_model(step: impl Step, model: Option<ModelConfig>) -> Scope {
    Scope::new(
        Arc::new(
            Flow::builder("configured")
                .entry("start")
                .step("start", step)
                .exit("done")
                .build()
                .unwrap(),
        ),
        state(),
        AutoCheckpointConfig::Unbounded,
        model,
    )
}

fn unchanged(scope: &Scope) {
    assert_eq!(scope.current_step().0, "start");
    assert_eq!(scope.state().get::<u64>("count"), Some(&7));
    assert_eq!(scope.state().get::<String>("message").unwrap(), "previous");
    assert!(scope.trace().entries.is_empty());
    assert!(!scope.is_finished());
}

#[test]
fn serializable_wiring_drives_typed_updates_and_trace() {
    let encoded = serde_json::to_string(&wiring()).unwrap();
    let wiring: StepWiring = serde_json::from_str(&encoded).unwrap();
    let action = StructuredStepBuilder::operation(|context: &CounterContext| {
        Ok(json!({"count": context.count + 1, "protected": 0}))
    });
    let mut scope = scope(action.with_wiring(wiring).build().unwrap());
    scope.advance().unwrap();
    assert!(scope.is_finished());
    assert_eq!(scope.current_step().0, "done");
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
    assert_eq!(scope.state().get::<u64>("protected"), Some(&99));
    assert_eq!(scope.state().get::<String>("message").unwrap(), "");
    assert!(matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Count 7 -> 8"));
}

#[test]
fn one_builder_chain_and_imported_json_execute_the_same_step() {
    fn increment(context: &CounterContext) -> Result<CounterContext, String> {
        Ok(CounterContext {
            count: context.count + 1,
        })
    }
    let authored = StructuredStepBuilder::operation(increment)
        .description("Increment")
        .bind_state("count", "count")
        .update("count", "/count")
        .next("done")
        .summary("Count {{ result.count }}");
    let imported = StructuredStepBuilder::operation(increment).with_wiring(
        serde_json::from_str(
            r#"{
                "description": "Increment",
                "bindings": [
                    {"from": {"kind": "state", "field": "count"}, "to": {"kind": "context", "name": "count"}},
                    {"from": {"kind": "result", "pointer": "/count"}, "to": {"kind": "state", "field": "count"}}
                ],
                "next": {"kind": "fixed", "next": "done"},
                "summary": "Count {{ result.count }}"
            }"#,
        )
        .unwrap(),
    );
    for builder in [authored, imported] {
        let mut scope = scope(builder.build().unwrap());
        scope.advance().unwrap();
        assert_eq!(scope.state().get::<u64>("count"), Some(&8));
        assert_eq!(scope.state().get::<String>("message").unwrap(), "previous");
        assert_eq!(scope.current_step().0, "done");
        assert!(scope.is_finished());
        assert!(matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Count 8"));
    }
}

#[test]
fn building_does_not_execute_callbacks_and_prepared_context_need_not_deserialize() {
    #[derive(Serialize)]
    struct Prepared {
        count: u64,
    }
    let preparations = Arc::new(AtomicUsize::new(0));
    let operations = Arc::new(AtomicUsize::new(0));
    let counted_preparations = preparations.clone();
    let counted_operations = operations.clone();
    let builder = StructuredStepBuilder::operation(move |context: &Prepared| {
        counted_operations.fetch_add(1, Ordering::SeqCst);
        Ok(context.count)
    })
    .with_context(move |input: CounterContext| {
        counted_preparations.fetch_add(1, Ordering::SeqCst);
        Ok(Prepared { count: input.count + 1 })
    })
    .bind_state("count", "count")
    .update("count", "")
    .next("done");
    assert!(builder.clone().summary("{{").build().is_err());
    let step = builder.build().unwrap();
    assert_eq!(preparations.load(Ordering::SeqCst), 0);
    assert_eq!(operations.load(Ordering::SeqCst), 0);
    let mut scope = scope(step);
    scope.advance().unwrap();
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert_eq!(operations.load(Ordering::SeqCst), 1);
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
}

#[test]
fn summary_can_read_unbound_state_context_and_result_before_commit() {
    let wiring = StructuredStepBuilder::new().with_wiring(wiring()).summary(
        "State {{ state.count }} / unbound {{ state.protected }} / context {{ context.count }} / result {{ result.count }}",
    ).wiring().clone();
    let mut scope = scope(
        StructuredStepBuilder::operation(|context: &CounterContext| Ok(json!({"count": context.count + 1})))
            .with_wiring(wiring)
            .build()
            .unwrap(),
    );
    scope.advance().unwrap();
    assert!(matches!(
        &scope.trace().entries[0].summary,
        TraceSummary::Summary(text) if text == "State 7 / unbound 99 / context 7 / result 8"
    ));
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
}

#[test]
fn input_is_optional_and_can_be_attached_to_the_same_builder_configuration() {
    let mut builder = InputSpec::builder();
    let field = builder.field("answer", "Answer", String::new()).text_input();
    let input = builder.finish(field).unwrap();
    let builder = StructuredStepBuilder::operation(|context: &CounterContext| Ok(json!({"count": context.count + 1})))
        .with_wiring(wiring());
    let step = builder.clone().with_input(input.clone()).build().unwrap();
    let waiting = scope(step.clone());
    assert!(step.input(&waiting).is_some());
    let automatic_builder = builder.summary("Updated {{ result.count }}");
    let built = automatic_builder.clone().build().unwrap();
    let mut automatic = scope(built.clone());
    assert!(built.input(&automatic).is_none());
    automatic.run_until_input().unwrap();
    assert!(automatic.is_finished());
    assert_eq!(automatic.state().get::<u64>("count"), Some(&8));
    let mut waiting = scope(automatic_builder.with_input(input).build().unwrap());
    assert!(waiting.run_until_input().unwrap().is_some());
    assert_eq!(waiting.state().get::<u64>("count"), Some(&7));
    waiting.input_handle().submit_input(r#"{"answer":"continue"}"#).unwrap();
    waiting.run_until_input().unwrap();
    assert_eq!(waiting.state().get::<u64>("count"), Some(&8));
}

#[test]
fn bad_bindings_and_destinations_fail_before_the_action() {
    let invalid = [
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .bind_state("count", "protected")
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .bind_state("missing", "not_a_field")
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .update("count", "/count")
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .update("missing", "/count")
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .update("protected", "not-a-pointer")
            .wiring()
            .clone(),
        StepWiring {
            next: crate::NextStep::Fixed {
                next: Some("unknown".into()),
            },
            ..wiring()
        },
        StepWiring {
            bindings: vec![],
            ..wiring()
        },
    ];
    for wiring in invalid {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let step = StructuredStepBuilder::operation(move |_: &CounterContext| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"count": 8}))
        })
        .with_wiring(wiring)
        .build();
        let Ok(step) = step else {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            continue;
        };
        let mut scope = scope(step);
        assert!(scope.advance().is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        unchanged(&scope);
    }
}

#[test]
fn invalid_prepared_context_updates_fail_before_the_action() {
    for (prepared, expected_error) in [
        (json!({}), "Step context is missing"),
        (json!({"count": "wrong type"}), "invalid State update count"),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let wiring = StructuredStepBuilder::new()
            .description("Save prepared count")
            .next("done")
            .bind_state("count", "count")
            .update_from("count", ValueSource::Context { name: "count".into() })
            .wiring()
            .clone();
        let step = StructuredStepBuilder::operation(move |_: &JsonValue| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .with_wiring(wiring)
        .with_context(move |_: CounterContext| Ok(prepared.clone()))
        .build()
        .unwrap();
        let mut scope = scope(step);
        let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
        for _ in 0..2 {
            let error = scope.advance().unwrap_err();
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(error.to_string().contains(expected_error), "{error}");
            unchanged(&scope);
            assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
        }
    }
}

#[test]
fn preflight_rejects_decoders_that_return_a_different_concrete_state_type() {
    #[derive(Clone)]
    struct WrongTypeValue(u64);

    impl Value for WrongTypeValue {
        fn encode(&self) -> String {
            self.0.to_string()
        }

        fn decode(&self, encoded: &str) -> Result<Box<dyn Value>, String> {
            // Valid JSON, but the returned u64 does not preserve this State field's type.
            Ok(Box::new(
                serde_json::from_str::<u64>(encoded).map_err(|error| error.to_string())?,
            ))
        }

        fn clone_box(&self) -> Box<dyn Value> {
            Box::new(self.clone())
        }
    }

    for source in [
        ValueSource::Constant { value: json!(8) },
        ValueSource::Context { name: "count".into() },
    ] {
        for model_enabled in [false, true] {
            let actions = Arc::new(AtomicUsize::new(0));
            let models = Arc::new(AtomicUsize::new(0));
            let called = actions.clone();
            let builder = StructuredStepBuilder::operation(move |_: &JsonValue| {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .with_context(|_: JsonValue| Ok(json!({"count": 8})))
            .update_from("count", source.clone())
            .next("done");
            let builder = if model_enabled {
                builder.with_model(count_template())
            } else {
                builder
            };
            let flow = Flow::builder("invalid-state-codec")
                .entry("start")
                .step("start", builder.build().unwrap())
                .exit("done")
                .build()
                .unwrap();
            let mut scope = Scope::new(
                Arc::new(flow),
                State::builder()
                    .field("count", "Custom counter", WrongTypeValue(7))
                    .build()
                    .unwrap(),
                AutoCheckpointConfig::Unbounded,
                Some(ModelConfig::new("action-model", FailingBackend(models.clone()))),
            );
            let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
            for _ in 0..2 {
                let error = scope.advance().unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("decoder returned a different concrete value type"),
                    "{error}"
                );
                assert_eq!(actions.load(Ordering::SeqCst), 0);
                assert_eq!(models.load(Ordering::SeqCst), 0);
                assert_eq!(scope.state().get::<WrongTypeValue>("count").unwrap().0, 7);
                assert_eq!(scope.current_step().0, "start");
                assert!(scope.trace().entries.is_empty());
                assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
            }
        }
    }
}

#[test]
fn invalid_summary_syntax_fails_before_the_action() {
    for summary in ["{{", "{% if result.count %}"] {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let result = StructuredStepBuilder::operation(move |_: &CounterContext| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"count": 8}))
        })
        .with_wiring(wiring())
        .summary(summary)
        .build();
        assert!(result.err().unwrap().contains("parse Step summary"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn failed_input_presentation_rejects_the_turn_before_model_or_action() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let builder = StructuredStepBuilder::operation(move |_: &CounterContext| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"count": 8}))
    })
    .with_wiring(wiring());
    for model_enabled in [false, true] {
        let models = Arc::new(AtomicUsize::new(0));
        let builder = if model_enabled {
            builder.clone().with_model(count_template())
        } else {
            builder.clone()
        };
        let step = builder
            .with_fallible_input_factory(|_| Err("input presentation failed".to_owned().into()))
            .build()
            .unwrap();
        let mut failed = scope_with_model(
            step,
            Some(ModelConfig::new("action-model", FailingBackend(models.clone()))),
        );
        let checkpoints = failed.checkpoint_ids().cloned().collect::<Vec<_>>();
        for _ in 0..2 {
            assert!(
                failed
                    .run_until_input()
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("input presentation failed")
            );
            assert!(failed.input_handle().input_spec().is_none());
            unchanged(&failed);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(models.load(Ordering::SeqCst), 0);
            assert!(failed.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
        }
    }
    let mut automatic = scope(builder.build().unwrap());
    assert!(automatic.run_until_input().unwrap().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn fallible_input_presentation_uses_state_before_the_action() {
    let step = StructuredStepBuilder::operation(|context: &CounterContext| Ok(json!({"count": context.count + 1})))
        .with_wiring(wiring())
        .with_fallible_input_factory(|scope| {
            let mut builder = InputSpec::builder();
            let prompt = format!("Current count: {}", scope.state().get::<u64>("count").unwrap());
            let field = builder.field("answer", prompt, String::new()).text_input();
            builder.finish(field).map_err(Into::into)
        })
        .build()
        .unwrap();
    let mut scope = scope(step);
    let (input, _) = scope.run_until_input().unwrap().unwrap();
    assert_eq!(input.field_schema("answer").unwrap()["title"], "Current count: 7");
    scope.input_handle().submit_input(r#"{"answer":"continue"}"#).unwrap();
    scope.run_until_input().unwrap();
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
}

#[test]
fn processing_decode_and_summary_errors_do_not_partially_commit() {
    for (wiring, result) in [
        (wiring(), Err("processor rejected the result".to_owned())),
        (wiring(), Ok(json!({"wrong": 8}))),
        (wiring(), Ok(json!({"count": "wrong type"}))),
        (
            StructuredStepBuilder::new()
                .with_wiring(wiring())
                .summary("{{ result.missing }}")
                .wiring()
                .clone(),
            Ok(json!({"count": 8})),
        ),
        (
            StructuredStepBuilder::new()
                .with_wiring(wiring())
                .summary("{{ state.missing }}")
                .wiring()
                .clone(),
            Ok(json!({"count": 8})),
        ),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let action = StructuredStepBuilder::operation(move |_: &CounterContext| {
            counted.fetch_add(1, Ordering::SeqCst);
            result.clone()
        });
        let mut scope = scope(action.with_wiring(wiring).build().unwrap());
        let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
        assert!(scope.advance().is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        unchanged(&scope);
        assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
    }
}

#[test]
fn finalization_actions_run_in_order_and_stop_at_the_first_error() {
    for fail_at in [None, Some(0), Some(1), Some(2)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let first = calls.clone();
        let second = calls.clone();
        let third = calls.clone();
        let step = StructuredStepBuilder::operation(move |context: &CounterContext| {
            assert_eq!(first.fetch_add(1, Ordering::SeqCst), 0);
            if fail_at == Some(0) {
                return Err("first action failed".into());
            }
            Ok(context.count + 1)
        })
        .action(move |context, count| {
            assert_eq!(second.fetch_add(1, Ordering::SeqCst), 1);
            assert_eq!(context.count, 7);
            assert_eq!(count, 8);
            if fail_at == Some(1) {
                return Err("second action failed".into());
            }
            Ok((count * 2).to_string())
        })
        .action(move |context, text| {
            assert_eq!(third.fetch_add(1, Ordering::SeqCst), 2);
            assert_eq!(context.count, 7);
            assert_eq!(text, "16");
            if fail_at == Some(2) {
                return Err("third action failed".into());
            }
            Ok(CounterContext {
                count: text.parse::<u64>().unwrap() + 3,
            })
        })
        .with_wiring(wiring())
        .build()
        .unwrap();
        let mut scope = scope(step);
        let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
        let result = scope.advance();
        if let Some(index) = fail_at {
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), index + 1);
            unchanged(&scope);
            assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
        } else {
            result.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert_eq!(scope.state().get::<u64>("count"), Some(&19));
            assert_eq!(scope.state().get::<String>("message").unwrap(), "");
            assert!(
                matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Count 7 -> 19")
            );
            assert!(scope.is_finished());
        }
    }
}

#[test]
fn ordinary_step_finalization_executes_the_action_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let step = StructuredStepBuilder::operation(move |context: &CounterContext| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"count": context.count + 1}))
    })
    .with_wiring(wiring())
    .build()
    .unwrap();
    let scope = scope(step.clone());
    let TemplateSpec::Skip(mut proposal) = step.model_template(&scope) else {
        panic!("structured Steps use the ordinary finalization path");
    };
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    step.finalize(&scope, &mut proposal).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let TurnProposal::Advance { next, updates } = proposal else {
        unreachable!()
    };
    assert_eq!(next.unwrap().0, "done");
    assert_eq!(updates.get::<u64>("count"), Some(&8));
    unchanged(&scope);
}

#[test]
fn model_response_fixtures_use_the_same_decode_processing_and_commit_path() {
    for text in [Some("2"), Some("invalid JSON"), Some("\"wrong type\""), None] {
        let action = StructuredStepBuilder::operation(move |_: &CounterContext| {
            Ok(ModelResponse {
                text: text.map(str::to_owned),
                finish_reason: None,
                usage: None,
                web_search_used: false,
                sources: vec![],
                raw_json: JsonValue::Null,
                http: lyquid::http::Response {
                    status: 200,
                    headers: vec![],
                    body: vec![],
                },
            })
        })
        .action(|_, response| {
            let text = response.text.ok_or_else(|| "model returned no text".to_owned())?;
            serde_json::from_str::<u64>(&text).map_err(|error| format!("decode model result: {error}"))
        })
        .action(|context, count| Ok(json!({"count": context.count + count})));
        let mut scope = scope(action.with_wiring(wiring()).build().unwrap());
        let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
        if text == Some("2") {
            scope.advance().unwrap();
            assert!(scope.is_finished());
            assert_eq!(scope.state().get::<u64>("count"), Some(&9));
            assert_eq!(scope.state().get::<u64>("protected"), Some(&99));
        } else {
            assert!(scope.advance().is_err());
            unchanged(&scope);
            assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
        }
    }
}

#[test]
fn revisiting_a_step_prepares_a_fresh_context_from_committed_state() {
    let step = StructuredStepBuilder::operation(|context: &CounterContext| {
        Ok(json!({"count": context.count, "route": if context.count < 9 { "again" } else { "finish" }}))
    })
    .with_wiring(wiring())
    .route_by("/route", [("again", "start"), ("finish", "done")])
    .with_context(|input: CounterContext| Ok(CounterContext { count: input.count + 1 }))
    .build()
    .unwrap();
    let mut scope = scope(step);
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, "start");
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
    scope.advance().unwrap();
    assert!(scope.is_finished());
    assert_eq!(scope.state().get::<u64>("count"), Some(&9));
    assert_eq!(scope.trace().entries.len(), 2);
}

#[test]
fn public_value_access_keeps_committed_and_step_scoped_data_separate() {
    let action = StructuredStepBuilder::operation(|_: &CounterContext| Ok(json!({"count": 8})));
    let mut scope = scope(action.with_wiring(wiring()).build().unwrap());
    scope.set(StateNamespace::Default, "count".into(), Some(Box::new(11_u64)));
    scope.set(
        StateNamespace::Input,
        "count".into(),
        Some(Box::new(String::from("answer"))),
    );
    assert_eq!(scope.state().get::<u64>("count"), Some(&7));
    assert_eq!(scope.state().get_value("count").unwrap().encode(), "7");
    assert_eq!(scope.get::<u64>(StateNamespace::Default, "count"), Some(&11));
    assert_eq!(
        scope.get_value(StateNamespace::Default, "count").unwrap().encode(),
        "11"
    );
    assert_eq!(
        scope.get::<String>(StateNamespace::Input, "count").map(String::as_str),
        Some("answer")
    );
    assert_eq!(
        scope.get_value(StateNamespace::Input, "count").unwrap().encode(),
        "\"answer\""
    );
    assert!(scope.state().get_value("unknown").is_none());
    assert!(scope.get_value(StateNamespace::Default, "unknown").is_none());
    assert!(scope.get_value(StateNamespace::Input, "unknown").is_none());
    assert!(
        scope
            .state()
            .get_value("count")
            .unwrap()
            .decode("\"wrong type\"")
            .is_err()
    );
    unchanged(&scope);
}

#[test]
fn typed_context_preparation_and_result_mapping_do_not_need_scope_callbacks() {
    let action = StructuredStepBuilder::operation(|context: &CounterContext| Ok(context.count))
        .action(|_, count| Ok(json!({"count": count * 2})));
    let step = action
        .with_wiring(wiring())
        .with_context(|mut input: CounterContext| {
            input.count += 1;
            Ok(input)
        })
        .build()
        .unwrap();
    let mut scope = scope(step);
    scope.advance().unwrap();
    assert_eq!(scope.state().get::<u64>("count"), Some(&16));
}

#[test]
fn configured_input_reuses_typed_atomic_input_contracts() {
    let wiring = StructuredStepBuilder::new()
        .description("Collect a message")
        .next("done")
        .update_from("message", ValueSource::Input { name: "answer".into() })
        .update_from("count", ValueSource::Input { name: "count".into() })
        .wiring()
        .clone();
    let mut builder = InputSpec::builder();
    let answer = builder.field("answer", "Your message", String::new()).text_input();
    let count = builder.field("count", "Count", 0_u64).number_input();
    let submit = builder.submit("Continue");
    let layout = builder.ui().column(vec![answer, count, submit]);
    let step = StructuredStepBuilder::operation(|context: &JsonValue| {
        assert_eq!(context, &json!({}), "direct Input-to-State bindings bypass Context");
        Ok(json!("unused result"))
    })
    .with_wiring(wiring)
    .with_input(builder.finish(layout).unwrap())
    .build()
    .unwrap();
    let mut scope = scope(step.clone());
    let input = step.input(&scope).unwrap();
    assert_eq!(input.field_schema("answer").unwrap()["type"], "string");
    assert!(scope.run_until_input().unwrap().is_some());
    let handle = scope.input_handle();
    assert!(
        handle
            .submit_input(r#"{"answer":"discard me","count":"wrong type"}"#)
            .is_err()
    );
    assert!(scope.get_value(StateNamespace::Input, "answer").is_none());
    unchanged(&scope);
    handle.submit_input(r#"{"answer":" exact text ","count":8}"#).unwrap();
    assert!(scope.run_until_input().unwrap().is_none());
    assert_eq!(scope.state().get::<String>("message").unwrap(), " exact text ");
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
    assert!(scope.get_value(StateNamespace::Input, "answer").is_none());
    assert!(scope.is_finished());
}

#[test]
fn json_input_drives_typed_actions_and_atomic_updates() {
    #[derive(Deserialize)]
    struct Configuration {
        input: InputSpec,
    }
    let configuration: Configuration = serde_json::from_value(json!({
        "input": {
            "ui": {
                "root": "root",
                "components": [
                    {"id": "root", "component": "Column", "children": ["answer", "count"]},
                    {"id": "answer", "component": "TextField", "label": "Answer", "variant": "shortText",
                        "value": {"path": "/fields/answer"}},
                    {"id": "count", "component": "TextField", "label": "Count", "variant": "number",
                        "value": {"path": "/fields/count"}}
                ],
                "data": {}
            },
            "schema": {
                "type": "object", "additionalProperties": false,
                "properties": {
                    "answer": {"type": "string", "minLength": 1},
                    "count": {"type": "integer", "minimum": 0, "maximum": 20}
                },
                "required": ["answer", "count"]
            }
        }
    }))
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let called = calls.clone();
    let step = StructuredStepBuilder::operation(move |context: &CounterContext| {
        called.fetch_add(1, Ordering::SeqCst);
        Ok(CounterContext {
            count: context.count + 1,
        })
    })
    .with_input(configuration.input)
    .bind_input("count", "count")
    .update("count", "/count")
    .update_from("message", ValueSource::Input { name: "answer".into() })
    .next("done")
    .build()
    .unwrap();
    let mut scope = scope(step);
    assert!(scope.run_until_input().unwrap().is_some());
    let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
    for invalid in [
        r#"{"answer":"discard","count":"8"}"#,
        r#"{"answer":"discard","count":21}"#,
        r#"{"answer":"","count":8}"#,
    ] {
        assert!(scope.input_handle().submit_input(invalid).is_err());
        assert!(scope.get_value(StateNamespace::Input, "answer").is_none());
        assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        unchanged(&scope);
    }
    scope
        .input_handle()
        .submit_input(r#"{"answer":"accepted","count":8}"#)
        .unwrap();
    scope.run_until_input().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(scope.state().get::<u64>("count"), Some(&9));
    assert_eq!(scope.state().get::<String>("message").unwrap(), "accepted");
    assert_eq!(scope.trace().entries.len(), 1);
    assert!(scope.get_value(StateNamespace::Input, "count").is_none());
    assert!(scope.is_finished());
}

#[test]
fn mounted_configured_action_uses_normal_child_join_and_checkpoint_restore() {
    let action = StructuredStepBuilder::operation(|context: &CounterContext| Ok(json!({"count": context.count + 1})));
    let child = Flow::builder("child")
        .entry("start")
        .step("start", action.with_wiring(wiring()).build().unwrap())
        .exit("done")
        .build()
        .unwrap();
    let parent = Flow::builder("parent")
        .entry("child")
        .flow(
            "child",
            child,
            ExitTransitions::new().transition("done", "finished").unwrap(),
            TraceMode::Expanded,
        )
        .exit("finished")
        .build()
        .unwrap();
    let mut scope = Scope::new(Arc::new(parent), state(), AutoCheckpointConfig::Unbounded, None);
    let checkpoint = scope.checkpoint();
    scope.advance().unwrap();
    assert!(scope.is_finished());
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
    assert!(matches!(&scope.trace().entries[0].summary, TraceSummary::SubFlow(_)));
    scope.restore(&checkpoint).unwrap();
    assert_eq!(scope.state().get::<u64>("count"), Some(&7));
    assert!(scope.trace().entries.is_empty());
}

struct FailingBackend(Arc<AtomicUsize>);

impl Backend for FailingBackend {
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
        assert_eq!(request.model, "action-model");
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(LlmError::Backend {
            provider: "fixture".into(),
            message: "intentional rejection".into(),
        })
    }

    fn parse_response(&self, _: JsonApiResponse) -> LlmResult<ModelResponse> {
        unreachable!("this fixture never sends HTTP")
    }
}

fn count_template() -> ModelTemplate {
    ModelTemplate::new(
        "Increment {{ state.count }}",
        vec![(Some("done".into()), "When complete".into())],
        vec![("count".into(), "The incremented count".into())],
    )
}

#[test]
fn model_phase_uses_flow_usage_reporting_and_does_not_run_finalization_after_failure() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(AtomicUsize::new(0));
    let finalized = Arc::new(AtomicUsize::new(0));
    let observed = observations.clone();
    let processed = finalized.clone();
    let action = StructuredStepBuilder::<CounterContext, u64>::proposed("count").action(move |_, count| {
        processed.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"count": count}))
    });
    let step = action
        .with_wiring(wiring())
        .with_model(count_template())
        .build()
        .unwrap();
    let model = ModelConfig::new("action-model", FailingBackend(calls.clone()));
    let mut scope = scope_with_model(step, Some(model)).on_usage(move |_, usage| {
        assert!(usage.is_none());
        observed.fetch_add(1, Ordering::SeqCst);
    });
    let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
    assert!(matches!(scope.advance(), Err(FlowError::Model(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(observations.load(Ordering::SeqCst), 1);
    assert_eq!(finalized.load(Ordering::SeqCst), 0);
    unchanged(&scope);
    assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
}

#[test]
fn direct_bindings_read_committed_state_and_prepared_context_without_chaining_writes() {
    let wiring = StructuredStepBuilder::new()
        .description("Copy")
        .next("done")
        .bind_state("count", "count")
        .constant("count", 8)
        .update_from("protected", ValueSource::State { field: "count".into() })
        .update_from("message", ValueSource::Context { name: "label".into() })
        .wiring()
        .clone();
    let wiring = serde_json::from_str(&serde_json::to_string(&wiring).unwrap()).unwrap();
    let step = StructuredStepBuilder::operation(|_: &JsonValue| Ok(json!("unused result")))
        .with_wiring(wiring)
        .with_context(|input: CounterContext| Ok(json!({"label": format!("Count {}", input.count)})))
        .build()
        .unwrap();
    let mut scope = scope(step.clone());
    scope.set(StateNamespace::Default, "count".into(), Some(Box::new(100_u64)));
    let mut proposal = TurnProposal::Advance {
        next: None,
        updates: StateUpdates::default(),
    };
    step.finalize(&scope, &mut proposal).unwrap();
    let TurnProposal::Advance { updates, .. } = proposal else {
        unreachable!()
    };
    assert_eq!(updates.get::<u64>("count"), Some(&8));
    assert_eq!(updates.get::<u64>("protected"), Some(&7));
    assert_eq!(updates.get::<String>("message").unwrap(), "Count 7");
    unchanged(&scope);
}

#[test]
fn direct_execution_id_binding_and_invalid_source_recovery_use_normal_turn_commit() {
    let identify = StructuredStepBuilder::new()
        .description("Identify")
        .next("done")
        .update_from("message", ValueSource::ExecutionId)
        .wiring()
        .clone();
    let mut identified = scope(
        StructuredStepBuilder::operation(|_: &JsonValue| Ok(()))
            .with_wiring(identify)
            .build()
            .unwrap(),
    );
    let id = identified.execution_id().to_string();
    identified.advance().unwrap();
    assert_eq!(identified.state().get::<String>("message"), Some(&id));
    for source in [
        ValueSource::State {
            field: "missing".into(),
        },
        ValueSource::State {
            field: "message".into(),
        },
        ValueSource::Input { name: "missing".into() },
        ValueSource::Context { name: "missing".into() },
        ValueSource::Context {
            name: "wrong_type".into(),
        },
    ] {
        let wiring = StructuredStepBuilder::new()
            .with_wiring(wiring())
            .update_from("protected", source)
            .wiring()
            .clone();
        let step = StructuredStepBuilder::operation(|_: &JsonValue| Ok(json!({"count":8})))
            .with_wiring(wiring)
            .with_context(|_: CounterContext| Ok(json!({"wrong_type":"text"})))
            .build()
            .unwrap();
        let mut failed = scope(step);
        for _ in 0..2 {
            assert!(failed.advance().is_err());
            unchanged(&failed);
            assert_eq!(failed.state().get::<u64>("protected"), Some(&99));
        }
    }
}

#[test]
fn flat_bindings_are_order_independent_and_constants_can_supply_context() {
    for reverse in [false, true] {
        let mut wiring = StructuredStepBuilder::new()
            .description("Prepare and save")
            .next("done")
            .bind(
                ValueSource::Context { name: "label".into() },
                BindingTarget::State {
                    field: "message".into(),
                },
            )
            .bind(
                ValueSource::Result {
                    pointer: "/count".into(),
                },
                BindingTarget::State { field: "count".into() },
            )
            .bind(
                ValueSource::Constant { value: json!(10) },
                BindingTarget::Context { name: "count".into() },
            )
            .bind(
                ValueSource::State { field: "count".into() },
                BindingTarget::State {
                    field: "protected".into(),
                },
            )
            .summary("{{ state.count }} / {{ context.label }} / {{ result.count }}")
            .wiring()
            .clone();
        if reverse {
            wiring.bindings.reverse();
        }
        let step = StructuredStepBuilder::operation(|context: &JsonValue| {
            Ok(json!({"count": context["count"].as_u64().unwrap() + 1}))
        })
        .with_wiring(wiring)
        .with_context(|input: CounterContext| {
            Ok(json!({"count": input.count, "label": format!("Prepared {}", input.count)}))
        })
        .build()
        .unwrap();
        let mut scope = scope(step);
        scope.advance().unwrap();
        assert_eq!(scope.state().get::<u64>("count"), Some(&11));
        assert_eq!(scope.state().get::<u64>("protected"), Some(&7));
        assert_eq!(scope.state().get::<String>("message").unwrap(), "Prepared 10");
        assert!(
            matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "7 / Prepared 10 / 11")
        );
    }
}

#[test]
fn unavailable_context_sources_duplicate_targets_and_bad_constants_fail_before_action() {
    let context = BindingTarget::Context { name: "count".into() };
    for wiring in [
        StructuredStepBuilder::new()
            .description("Invalid")
            .next("done")
            .bind(ValueSource::Result { pointer: "".into() }, context.clone())
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .description("Invalid")
            .next("done")
            .bind(ValueSource::Context { name: "count".into() }, context.clone())
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .description("Invalid")
            .next("done")
            .bind(
                ValueSource::Constant {
                    value: json!("wrong type"),
                },
                context.clone(),
            )
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .bind(ValueSource::Constant { value: json!(3) }, context)
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .bind(
                ValueSource::Constant { value: json!(3) },
                BindingTarget::State { field: "count".into() },
            )
            .wiring()
            .clone(),
        StructuredStepBuilder::new()
            .with_wiring(wiring())
            .bind(
                ValueSource::Constant { value: json!(3) },
                BindingTarget::Context { name: " ".into() },
            )
            .wiring()
            .clone(),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let step = StructuredStepBuilder::operation(move |_: &CounterContext| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"count": 8}))
        })
        .with_wiring(wiring)
        .build();
        let Ok(step) = step else {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            continue;
        };
        let mut scope = scope(step);
        assert!(scope.advance().is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        unchanged(&scope);
    }
}

/// Replaces only the model response, retaining configured input, preflight and finalization.
struct ProposedCountStep<S> {
    step: S,
    models: Arc<AtomicUsize>,
}

impl<S: Step> Step for ProposedCountStep<S> {
    fn description(&self, concise: bool) -> String {
        self.step.description(concise)
    }

    fn input(&self, scope: &Scope) -> Option<InputSpec> {
        self.step.input(scope)
    }

    fn model_template(&self, scope: &Scope) -> TemplateSpec {
        assert!(scope.get::<String>(StateNamespace::Input, "answer").is_some());
        assert!(matches!(self.step.model_template(scope), TemplateSpec::Template(_)));
        self.models.fetch_add(1, Ordering::SeqCst);
        let mut updates = StateUpdates::default();
        updates.set("count".into(), Some(Box::new(8_u64)));
        updates.set("protected".into(), Some(Box::new(101_u64)));
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some("done".into()),
            updates,
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        self.step.finalize(scope, proposal)
    }
}

#[test]
fn input_model_and_finalize_follow_flow_order_and_revise_the_existing_proposal() {
    let models = Arc::new(AtomicUsize::new(0));
    let finalized = Arc::new(AtomicUsize::new(0));
    let processed = finalized.clone();
    let model_calls = models.clone();
    let action = StructuredStepBuilder::<CounterContext, u64>::proposed("count").action(move |context, count| {
        assert_eq!(model_calls.load(Ordering::SeqCst), 1);
        assert_eq!(context.count, 7);
        processed.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"count": count * 2}))
    });
    let mut builder = InputSpec::builder();
    let answer = builder.field("answer", "Continue?", String::new()).text_input();
    let mut template = count_template();
    template
        .state_update_criteria
        .push(("protected".into(), "Updated metadata".into()));
    let step = action
        .with_wiring(wiring())
        .proposed_next()
        .with_input(builder.finish(answer).unwrap())
        .with_model(template)
        .build()
        .unwrap();
    let mut scope = scope(ProposedCountStep {
        step,
        models: models.clone(),
    });
    assert!(scope.run_until_input().unwrap().is_some());
    assert_eq!(models.load(Ordering::SeqCst), 0);
    assert_eq!(finalized.load(Ordering::SeqCst), 0);
    unchanged(&scope);
    scope.input_handle().submit_input(r#"{"answer":"yes"}"#).unwrap();
    assert!(scope.run_until_input().unwrap().is_none());
    assert_eq!(models.load(Ordering::SeqCst), 1);
    assert_eq!(finalized.load(Ordering::SeqCst), 1);
    assert_eq!(scope.state().get::<u64>("count"), Some(&16));
    assert_eq!(scope.state().get::<u64>("protected"), Some(&101));
    assert!(matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Count 7 -> 16"));
    assert!(scope.is_finished());
}

#[test]
fn model_restore_uses_scope_recovery_without_running_finalization_actions() {
    // Script the model proposal while retaining the configured preflight and finalizer.
    struct RestoreStep<S> {
        step: S,
        unknown_checkpoint: bool,
    }

    impl<S: Step> Step for RestoreStep<S> {
        fn description(&self, concise: bool) -> String {
            self.step.description(concise)
        }

        fn input(&self, scope: &Scope) -> Option<InputSpec> {
            self.step.input(scope)
        }

        fn model_template(&self, scope: &Scope) -> TemplateSpec {
            assert!(matches!(self.step.model_template(scope), TemplateSpec::Template(_)));
            TemplateSpec::Skip(TurnProposal::Restore {
                scope: if self.unknown_checkpoint {
                    "missing-checkpoint".into()
                } else {
                    scope.checkpoint_ids().next().unwrap().clone()
                },
            })
        }

        fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
            self.step.finalize(scope, proposal)
        }
    }

    for unknown_checkpoint in [false, true] {
        let preparations = Arc::new(AtomicUsize::new(0));
        let prepared = preparations.clone();
        let step = StructuredStepBuilder::<CounterContext, u64>::proposed("count")
            .action(|_, _| -> Result<JsonValue, String> { panic!("restore must skip finalization actions") })
            .with_context(move |context: CounterContext| {
                prepared.fetch_add(1, Ordering::SeqCst);
                Ok(context)
            })
            .with_wiring(wiring())
            .proposed_next()
            .summary("{{ result.missing }}")
            .with_model(count_template())
            .build()
            .unwrap();
        let flow = Flow::builder("configured-restore")
            .entry("start")
            .step(
                "start",
                StructuredStepBuilder::new()
                    .constant("count", 8)
                    .next("restore")
                    .build()
                    .unwrap(),
            )
            .step(
                "restore",
                RestoreStep {
                    step,
                    unknown_checkpoint,
                },
            )
            .exit("done")
            .build()
            .unwrap();
        let mut scope = Scope::new(Arc::new(flow), state(), AutoCheckpointConfig::Disabled, None);
        let checkpoint = scope.checkpoint();
        scope.advance().unwrap();
        assert_eq!(scope.current_step().0, "restore");
        assert_eq!(scope.state().get::<u64>("count"), Some(&8));
        assert_eq!(scope.trace().entries.len(), 1);

        let result = scope.advance();
        if unknown_checkpoint {
            assert_eq!(
                result.unwrap_err().to_string(),
                "unknown Scope checkpoint missing-checkpoint"
            );
            assert_eq!(scope.current_step().0, "restore");
            assert_eq!(scope.state().get::<u64>("count"), Some(&8));
            assert_eq!(scope.trace().entries.len(), 1);
        } else {
            result.unwrap();
            unchanged(&scope);
        }
        assert_eq!(scope.state().get::<String>("message").unwrap(), "previous");
        assert_eq!(
            preparations.load(Ordering::SeqCst),
            1,
            "only model preflight prepares context"
        );
        assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == vec![checkpoint]);
    }
}

#[test]
fn deterministic_routing_excludes_restores_before_actions() {
    for next in [
        crate::NextStep::Fixed {
            next: Some("done".into()),
        },
        crate::NextStep::Fixed { next: None },
        crate::NextStep::Result {
            pointer: "/route".into(),
            cases: vec![crate::NextCase {
                value: "finish".into(),
                next: Some("done".into()),
            }],
        },
    ] {
        let mut wiring = wiring();
        wiring.next = next;
        let builder = StructuredStepBuilder::operation_with_config(
            "must_not_run",
            (),
            |_: &CounterContext, &()| -> Result<JsonValue, String> {
                panic!("a restore cannot trigger a forward action")
            },
        )
        .with_wiring(wiring)
        .with_model(count_template());
        assert!(!builder.configuration().unwrap().model.unwrap().allow_restore);
        let step = builder.build().unwrap();
        assert!(!step.configuration().unwrap().model.as_ref().unwrap().allow_restore);
        let mut scope = scope(step.clone());
        let checkpoint = scope.checkpoint();
        let TemplateSpec::Template(template) = step.model_template(&scope) else {
            panic!("the model preflight should succeed");
        };
        assert!(!template.allow_restore);
        let mut proposal = TurnProposal::Restore {
            scope: checkpoint.clone(),
        };
        assert_eq!(
            step.finalize(&scope, &mut proposal).err().unwrap().to_string(),
            "restore proposals are not permitted by the configured routing",
        );
        assert!(matches!(proposal, TurnProposal::Restore { scope } if scope == checkpoint));
        unchanged(&scope);
        scope.restore(&checkpoint).unwrap();
    }
}

#[test]
fn model_and_custom_processing_are_independently_optional() {
    let builder = StructuredStepBuilder::new()
        .description("Pass through")
        .next("done")
        .constant("message", "saved");
    let step = builder.clone().with_model(count_template()).build().unwrap();
    let existing = scope(step.clone());
    assert!(matches!(step.model_template(&existing), TemplateSpec::Template(_)));
    let mut updates = StateUpdates::default();
    updates.set("count".into(), Some(Box::new(9_u64)));
    let mut proposal = TurnProposal::Advance {
        next: Some("done".into()),
        updates,
    };
    step.finalize(&existing, &mut proposal).unwrap();
    let TurnProposal::Advance { updates, .. } = proposal else {
        unreachable!()
    };
    assert_eq!(
        updates.get::<u64>("count"),
        Some(&9),
        "no processing preserves model updates"
    );
    assert_eq!(updates.get::<String>("message").unwrap(), "saved");
    unchanged(&existing);

    let disabled = builder.build().unwrap();
    let mut scope = scope(disabled.clone());
    assert!(disabled.input(&scope).is_none());
    assert!(matches!(disabled.model_template(&scope), TemplateSpec::Skip(_)));
    scope.advance().unwrap();
    assert!(scope.is_finished());
    assert_eq!(scope.state().get::<u64>("count"), Some(&7));
    assert_eq!(scope.state().get::<String>("message").unwrap(), "saved");
}

#[test]
fn model_preflight_rejects_static_prepared_and_action_contract_errors_before_calling_backend() {
    for case in 0..6 {
        let calls = Arc::new(AtomicUsize::new(0));
        let model = ModelConfig::new("action-model", FailingBackend(calls.clone()));
        let wiring = match case {
            0 => StructuredStepBuilder::new()
                .description("Invalid constant")
                .next("done")
                .constant("count", "wrong type")
                .wiring()
                .clone(),
            1 => StructuredStepBuilder::new()
                .description("Invalid context")
                .next("done")
                .update_from("count", ValueSource::Context { name: "count".into() })
                .wiring()
                .clone(),
            2 => StructuredStepBuilder::new()
                .description("Invalid summary")
                .next("done")
                .summary("{{")
                .wiring()
                .clone(),
            _ => StructuredStepBuilder::new()
                .description("Invalid action")
                .next("done")
                .wiring()
                .clone(),
        };
        let action = match case {
            3 => StructuredStepBuilder::<JsonValue, String>::proposed("count").action(|_, value| Ok(json!(value))),
            4 => StructuredStepBuilder::<JsonValue, u64>::proposed("protected").action(|_, value| Ok(json!(value))),
            _ => StructuredStepBuilder::new(),
        };
        let step = action
            .with_wiring(wiring)
            .with_context(move |_: JsonValue| {
                if case == 5 {
                    return Err("preparation rejected".into());
                }
                Ok(json!({"count": "wrong type"}))
            })
            .with_model(count_template())
            .build();
        let Ok(step) = step else {
            assert_eq!(case, 2, "only invalid summary syntax is Scope-independent here");
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            continue;
        };
        let mut scope = scope_with_model(step, Some(model));
        for _ in 0..2 {
            assert!(scope.advance().is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0, "case {case}");
            unchanged(&scope);
        }
    }
}

#[test]
fn finalization_rejects_a_missing_proposed_value_without_running_processors() {
    let processed = Arc::new(AtomicUsize::new(0));
    let counted = processed.clone();
    let action = StructuredStepBuilder::<CounterContext, u64>::proposed("count").action(move |_, count| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"count": count}))
    });
    let step = action
        .with_wiring(wiring())
        .with_model(count_template())
        .build()
        .unwrap();
    let scope = scope(step.clone());
    let mut proposal = TurnProposal::Advance {
        next: Some("done".into()),
        updates: StateUpdates::default(),
    };
    assert!(
        step.finalize(&scope, &mut proposal)
            .err()
            .unwrap()
            .to_string()
            .contains("proposed State field count")
    );
    assert_eq!(processed.load(Ordering::SeqCst), 0);
    unchanged(&scope);
}

#[test]
fn a_formatter_uses_the_same_ordered_action_api() {
    // A host-supplied action unit validates its own configuration before attachment.
    fn formatter(
        template: &str,
    ) -> Result<impl Fn(&crate::ActionContext<'_, JsonValue>, JsonValue) -> Result<String, String>, String> {
        let mut engine = tera::Tera::default();
        engine
            .add_raw_template("result", template)
            .map_err(|error| error.to_string())?;
        Ok(
            move |context: &crate::ActionContext<'_, JsonValue>, result: JsonValue| {
                let mut values = tera::Context::new();
                values.insert("context", context.prepared());
                values.insert("result", &result);
                engine
                    .render("result", &values)
                    .map_err(|error| format!("format Step result: {error}"))
            },
        )
    }
    assert!(formatter("{{").is_err());
    for (template, succeeds) in [("Count {{ result.count }}", true), ("{{ result.missing }}", false)] {
        let wiring = StructuredStepBuilder::new()
            .description("Format count")
            .next("done")
            .bind_state("count", "count")
            .update("message", "")
            .wiring()
            .clone();
        let mut scope = scope(
            StructuredStepBuilder::new()
                .action(formatter(template).unwrap())
                .action(|_, text| Ok(format!("{text}!")))
                .with_wiring(wiring)
                .build()
                .unwrap(),
        );
        if succeeds {
            scope.advance().unwrap();
            assert_eq!(scope.state().get::<String>("message").unwrap(), "Count 7!");
            assert_eq!(scope.state().get::<u64>("count"), Some(&7));
        } else {
            assert!(scope.advance().unwrap_err().to_string().contains("format Step result"));
            unchanged(&scope);
        }
    }
}

#[test]
fn named_action_results_survive_intervening_actions_but_not_the_next_turn() {
    let step = StructuredStepBuilder::new()
        .bind_state("count", "count")
        .action_named("saved", |context, _| {
            assert!(context.model_response().is_none());
            assert!(context.result("saved").is_none());
            Ok(json!({"count": context["count"].as_u64().unwrap() + 1}))
        })
        .action(|_, _| Ok("unrelated result"))
        .action(|context, previous| {
            assert_eq!(previous, "unrelated result");
            assert_eq!(
                context.result("saved").unwrap()["count"],
                context["count"].as_u64().unwrap() + 1
            );
            Ok(())
        })
        .update_from(
            "count",
            ValueSource::ActionResult {
                action: "saved".into(),
                pointer: "/count".into(),
            },
        )
        .next("start")
        .summary("Saved {{ actions.saved.count }}")
        .build()
        .unwrap();
    let mut scope = scope(step);
    for expected in [8, 9] {
        scope.advance().unwrap();
        assert_eq!(scope.state().get::<u64>("count"), Some(&expected));
        assert!(scope.model_response().is_none());
    }
    assert!(matches!(&scope.trace().entries[1].summary, TraceSummary::Summary(text) if text == "Saved 9"));
}

#[test]
fn failed_named_action_stops_the_chain_without_committing_saved_results() {
    let step = StructuredStepBuilder::new()
        .action_named("saved", |_, _| Ok(json!({"count": 99})))
        .action_named("failed", |_, _| -> Result<JsonValue, String> {
            Err("action failed".into())
        })
        .action(|_, _| -> Result<JsonValue, String> { panic!("later action must not run") })
        .update_from(
            "count",
            ValueSource::ActionResult {
                action: "saved".into(),
                pointer: "/count".into(),
            },
        )
        .next("done")
        .build()
        .unwrap();
    let mut scope = scope(step);
    assert!(scope.advance().unwrap_err().to_string().contains("action failed"));
    unchanged(&scope);
}

#[test]
fn named_result_configuration_is_validated_before_actions_run() {
    for name in ["", " "] {
        assert!(
            StructuredStepBuilder::new()
                .action_named(name, |_, _| Ok(()))
                .build()
                .is_err()
        );
    }
    assert!(
        StructuredStepBuilder::new()
            .action_named("same", |_, _| Ok(()))
            .action_named("same", |_, _| Ok(()))
            .build()
            .is_err()
    );
    assert!(
        StructuredStepBuilder::new()
            .update_from(
                "count",
                ValueSource::ActionResult {
                    action: "unknown".into(),
                    pointer: "".into()
                }
            )
            .build()
            .is_err()
    );
    assert!(
        StructuredStepBuilder::new()
            .update_from(
                "count",
                ValueSource::ModelResponse {
                    pointer: "/usage/total_tokens".into()
                }
            )
            .build()
            .is_err()
    );
}
