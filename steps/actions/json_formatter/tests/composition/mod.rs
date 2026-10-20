use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lyquid_flow::{
    AutoCheckpointConfig, Flow, ModelTemplate, Scope, State, StateUpdates, Step, TraceSummary, TurnProposal,
};
use lyquid_llm::{FinishReason, ModelResponse, Usage};
use lyquid_structured_step::{ActionContext, StructuredStepBuilder, ValueSource};
use lyquid_test::test;
use serde_json::{Value, json};

use crate::{JsonFormatterConfig, json_formatter, model_response_json_formatter};

pub(super) fn response(text: &str) -> ModelResponse {
    ModelResponse {
        text: Some(text.into()),
        finish_reason: Some(FinishReason::Stop),
        usage: Some(Usage {
            input_tokens: Some(2),
            output_tokens: Some(3),
            total_tokens: Some(5),
        }),
        web_search_used: true,
        sources: vec!["https://example.com/source".into()],
        raw_json: json!({"provider": "fixture"}),
        http: lyquid::http::Response {
            status: 200,
            headers: vec![lyquid::http::Header {
                name: "x-provider".into(),
                value: b"ok".to_vec(),
            }],
            body: b"{}".to_vec(),
        },
    }
}

fn scope(step: impl Step) -> Scope {
    let flow = Flow::builder("formatter")
        .entry("start")
        .step("start", step)
        .exit("done")
        .build()
        .unwrap();
    let state = State::builder()
        .field("count", "Count", 7_u64)
        .field("text", "Text", "before".to_owned())
        .build()
        .unwrap();
    Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Unbounded, None)
}

fn config() -> JsonFormatterConfig {
    JsonFormatterConfig::json_schema(json!({
        "type": "object",
        "properties": {"count": {"type": "integer", "minimum": 1}, "route": {"enum": ["finish"]}},
        "required": ["count", "route"],
        "additionalProperties": false
    }))
}

#[test]
fn formatter_runs_between_actions_before_bindings_routing_and_trace() {
    let step = StructuredStepBuilder::new()
        .bind_state("count", "count")
        .action(|context: &ActionContext<'_, Value>, previous: Value| {
            assert_eq!(context.prepared(), &previous);
            Ok(json!({"count": context["count"].as_u64().unwrap() + 1, "route": "finish"}).to_string())
        })
        .action(json_formatter(config()).unwrap())
        .action(|context, mut parsed| {
            assert_eq!(context["count"], 7);
            parsed["count"] = json!(parsed["count"].as_u64().unwrap() * 2);
            Ok(parsed)
        })
        .update("count", "/count")
        .route_by("/route", [("finish", "done")])
        .summary("Count {{ result.count }}")
        .build()
        .unwrap();
    let mut scope = scope(step);
    scope.advance().unwrap();
    assert_eq!(scope.state().get::<u64>("count"), Some(&16));
    assert!(scope.is_finished());
    assert!(matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Count 16"));
}

#[test]
fn invalid_json_or_schema_stops_later_actions_and_preserves_the_turn() {
    for text in ["not JSON", r#"{"count":0,"route":"finish"}"#] {
        let called = Arc::new(AtomicUsize::new(0));
        let count_calls = called.clone();
        let step = StructuredStepBuilder::operation(move |_: &Value| Ok(text.to_owned()))
            .action(json_formatter(config()).unwrap())
            .action(move |_, value| {
                count_calls.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })
            .constant("text", "changed")
            .update("count", "/count")
            .next("done")
            .build()
            .unwrap();
        let mut scope = scope(step);
        let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
        assert!(scope.advance().is_err());
        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert_eq!(scope.state().get::<u64>("count"), Some(&7));
        assert_eq!(scope.state().get::<String>("text").unwrap(), "before");
        assert_eq!(scope.current_step().0, "start");
        assert!(scope.trace().entries.is_empty());
        assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
    }
}

#[test]
fn named_formatter_output_survives_intervening_actions_and_supplies_bindings() {
    let step = StructuredStepBuilder::operation(|_: &Value| Ok(r#"{"count":8,"route":"finish"}"#.to_owned()))
        .action_named("formatted", json_formatter(config()).unwrap())
        .action(|_, _| Ok(false))
        .action(|context, previous| {
            assert!(!previous);
            assert_eq!(
                context.result("formatted"),
                Some(&json!({"count": 8, "route": "finish"}))
            );
            Ok(())
        })
        .update_from(
            "count",
            ValueSource::ActionResult {
                action: "formatted".into(),
                pointer: "/count".into(),
            },
        )
        .next("done")
        .summary("Count {{ actions.formatted.count }}")
        .build()
        .unwrap();
    let mut scope = scope(step);
    scope.advance().unwrap();
    assert_eq!(scope.state().get::<u64>("count"), Some(&8));
    assert!(scope.is_finished());
    assert!(matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Count 8"));
}

#[test]
fn model_response_formatter_rejects_missing_context_without_running_later_actions() {
    let step = StructuredStepBuilder::new()
        .action(|_, _| Ok("unrelated result"))
        .action_named("formatted", model_response_json_formatter(config()).unwrap())
        .action(|_, _| -> Result<Value, String> { panic!("later action must not run") })
        .constant("count", 99)
        .next("done")
        .build()
        .unwrap();
    let mut scope = scope(step);
    let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
    assert!(scope.advance().unwrap_err().to_string().contains("no model response"));
    assert_eq!(scope.state().get::<u64>("count"), Some(&7));
    assert_eq!(scope.current_step().0, "start");
    assert!(scope.trace().entries.is_empty());
    assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
}

#[test]
fn omitting_the_formatter_keeps_plain_text_usable() {
    let step = StructuredStepBuilder::operation(|_: &Value| Ok("Plain text { without JSON".to_owned()))
        .update("text", "")
        .next("done")
        .build()
        .unwrap();
    let mut scope = scope(step);
    scope.advance().unwrap();
    assert_eq!(
        scope.state().get::<String>("text").unwrap(),
        "Plain text { without JSON"
    );
}

#[test]
fn model_proposed_text_can_feed_the_formatter_without_replacing_flows_parser() {
    let step = StructuredStepBuilder::<Value, String>::proposed("text")
        .with_model(ModelTemplate::new(
            "Produce JSON text in the text field",
            vec![(Some("done".into()), "When complete".into())],
            vec![("text".into(), "JSON text with count and route".into())],
        ))
        .action(json_formatter(config()).unwrap())
        .update("count", "/count")
        .proposed_next()
        .summary("Count {{ result.count }}")
        .build()
        .unwrap();
    let scope = scope(step.clone());
    let mut updates = StateUpdates::default();
    updates.set(
        "text".into(),
        Some(Box::new(r#"{"count":8,"route":"finish"}"#.to_owned())),
    );
    // Fixture at the already-parsed TurnProposal boundary; no model or transport is involved.
    let mut proposal = TurnProposal::Advance {
        next: Some("done".into()),
        updates,
    };
    step.finalize(&scope, &mut proposal).unwrap();
    let TurnProposal::Advance { next, updates } = proposal else {
        unreachable!()
    };
    assert_eq!(next.unwrap().0, "done");
    assert_eq!(updates.get::<u64>("count"), Some(&8));
    assert_eq!(
        updates.get::<String>("text").unwrap(),
        r#"{"count":8,"route":"finish"}"#
    );
    assert_eq!(scope.state().get::<u64>("count"), Some(&7));
}
