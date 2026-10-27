use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lyquid_flow::{
    AutoCheckpointConfig, Flow, FlowError, InputSpec, Scope, State, StateUpdates, Step, TemplateSpec, TraceSummary,
    TurnProposal,
};
use lyquid_llm::{FinishReason, ModelResponse, Usage};
use lyquid_test::test;
use serde_json::json;

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

struct NativeStep<F> {
    proposal: TurnProposal,
    finalize: F,
}

impl<F> Step for NativeStep<F>
where
    F: Fn(&Scope, &mut TurnProposal) -> Result<TraceSummary, FlowError> + Send + Sync + 'static,
{
    fn description(&self, _: bool) -> String {
        "Format JSON".into()
    }

    fn input(&self, _: &Scope) -> Option<InputSpec> {
        None
    }

    fn model_template(&self, _: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(self.proposal.clone())
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        (self.finalize)(scope, proposal)
    }
}

fn proposal(updates: StateUpdates) -> TurnProposal {
    TurnProposal::Advance {
        next: Some("done".into()),
        updates,
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
        .field("count", "Count", lyquid_flow::Type::U64, json!(7_u64))
        .field("text", "Text", lyquid_flow::Type::String, json!("before".to_owned()))
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
fn native_finalizer_uses_formatted_values_before_core_commits_the_turn() {
    let format = json_formatter(config()).unwrap();
    let step = NativeStep {
        proposal: proposal(StateUpdates::default()),
        finalize: move |scope: &Scope, proposal: &mut TurnProposal| {
            let text = json!({"count": scope.state().get("count").and_then(serde_json::Value::as_u64).unwrap() + 1, "route": "finish"});
            let parsed = format(&text.to_string())?;
            let count = parsed["count"].as_u64().unwrap() * 2;
            let TurnProposal::Advance { next, updates } = proposal else {
                return Err("expected an advancing proposal".to_owned().into());
            };
            updates.set("count".into(), Some(json!(count)));
            if parsed["route"] == "finish" {
                *next = Some("done".into());
            }
            Ok(TraceSummary::Summary(format!("Count {count}")))
        },
    };
    let mut scope = scope(step);
    scope.advance().unwrap();
    assert_eq!(scope.state().get("count").and_then(serde_json::Value::as_u64), Some(16));
    assert!(scope.is_finished());
    assert_eq!(scope.trace().entries.len(), 1);
    assert_eq!(
        scope.trace().entries[0]
            .state
            .get("count")
            .and_then(serde_json::Value::as_u64),
        Some(16)
    );
    assert!(matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Count 16"));
}

#[test]
fn invalid_json_or_schema_rejects_partial_proposals_without_committing() {
    for text in ["not JSON", r#"{"count":0,"route":"finish"}"#] {
        let called = Arc::new(AtomicUsize::new(0));
        let count_calls = called.clone();
        let format = json_formatter(config()).unwrap();
        let step = NativeStep {
            proposal: proposal(StateUpdates::default()),
            finalize: move |_: &Scope, proposal: &mut TurnProposal| {
                let TurnProposal::Advance { updates, .. } = proposal else {
                    return Err("expected an advancing proposal".to_owned().into());
                };
                updates.set("text".into(), Some(json!("changed".to_owned())));
                let parsed = format(text)?;
                count_calls.fetch_add(1, Ordering::SeqCst);
                updates.set("count".into(), Some(json!(parsed["count"].as_u64().unwrap())));
                Ok(TraceSummary::Summary("Formatted".into()))
            },
        };
        let mut scope = scope(step);
        let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
        assert!(scope.advance().is_err());
        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert_eq!(scope.state().get("count").and_then(serde_json::Value::as_u64), Some(7));
        assert_eq!(
            scope.state().get("text").and_then(serde_json::Value::as_str).unwrap(),
            "before"
        );
        assert_eq!(scope.current_step().0, "start");
        assert!(scope.trace().entries.is_empty());
        assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
    }
}

#[test]
fn native_finalizer_rejects_a_missing_model_response_without_committing() {
    let format = model_response_json_formatter(config()).unwrap();
    let step = NativeStep {
        proposal: proposal(StateUpdates::default()),
        finalize: move |scope: &Scope, proposal: &mut TurnProposal| {
            let TurnProposal::Advance { updates, .. } = proposal else {
                return Err("expected an advancing proposal".to_owned().into());
            };
            updates.set("count".into(), Some(json!(99_u64)));
            format(scope.model_response())?;
            Ok(TraceSummary::Summary("Formatted".into()))
        },
    };
    let mut scope = scope(step);
    let checkpoints = scope.checkpoint_ids().cloned().collect::<Vec<_>>();
    assert!(scope.advance().unwrap_err().to_string().contains("no model response"));
    assert_eq!(scope.state().get("count").and_then(serde_json::Value::as_u64), Some(7));
    assert_eq!(scope.current_step().0, "start");
    assert!(scope.trace().entries.is_empty());
    assert!(scope.checkpoint_ids().cloned().collect::<Vec<_>>() == checkpoints);
}

#[test]
fn model_proposed_text_can_be_formatted_and_committed_by_a_native_step() {
    let format = json_formatter(config()).unwrap();
    let text = r#"{"count":8,"route":"finish"}"#;
    let mut updates = StateUpdates::default();
    updates.set("text".into(), Some(json!(text.to_owned())));
    let step = NativeStep {
        // Inject at the already-parsed TurnProposal boundary; no model or transport is involved.
        proposal: proposal(updates),
        finalize: move |_: &Scope, proposal: &mut TurnProposal| {
            let TurnProposal::Advance { updates, .. } = proposal else {
                return Err("expected an advancing proposal".to_owned().into());
            };
            let parsed = format(updates.get("text").and_then(serde_json::Value::as_str).unwrap())?;
            let count = parsed["count"].as_u64().unwrap();
            updates.set("count".into(), Some(json!(count)));
            Ok(TraceSummary::Summary(format!("Count {count}")))
        },
    };
    let mut scope = scope(step);
    scope.advance().unwrap();
    assert_eq!(scope.state().get("count").and_then(serde_json::Value::as_u64), Some(8));
    assert_eq!(
        scope.state().get("text").and_then(serde_json::Value::as_str).unwrap(),
        text
    );
    assert!(scope.is_finished());
    assert_eq!(scope.trace().entries.len(), 1);
    assert!(matches!(&scope.trace().entries[0].summary, TraceSummary::Summary(text) if text == "Count 8"));
}
