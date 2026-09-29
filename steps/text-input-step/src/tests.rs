use std::any::Any;
use std::sync::Arc;

use lyquid_flow::{AutoCheckpointConfig, Flow, State};
use lyquid_test::test;

use super::*;

fn scope() -> Scope {
    let flow = Flow::builder("text-entry")
        .entry("input")
        .exit("done")
        .step("input", TextInputStep::new("message", "Your message", "done"))
        .build()
        .unwrap();
    let state = State::builder()
        .field("message", "Latest text", String::new())
        .field("unrelated", "Application state", 7_u64)
        .build()
        .unwrap();
    Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Disabled, None)
}

#[test]
fn publishes_a_string_contract_and_dynamic_prompt_without_a_model() {
    let scope = scope();
    let step = TextInputStep::new("message", "Initial question", "done")
        .with_prompt(|scope| format!("Round {}", scope.state().get::<u64>("unrelated").unwrap()));
    let spec = step.input(&scope).unwrap();
    assert_eq!(spec.field_schema("message").unwrap()["title"], "Round 7");
    assert_eq!(spec.field_schema("message").unwrap()["type"], "string");
    let decoded = spec.decode(r#"{"message":"hello"}"#).unwrap();
    let message: &dyn Any = decoded["message"].as_ref();
    assert_eq!(message.downcast_ref::<String>().unwrap(), "hello");
    assert!(spec.decode("42").is_err());
    assert!(spec.decode(r#"{"message":42}"#).is_err());
    assert!(matches!(step.model_template(&scope), TemplateSpec::Skip(_)));
}

#[test]
fn persists_the_exact_message_and_discards_unrelated_proposals() {
    let mut scope = scope();
    let step = TextInputStep::new("message", "Your message", "done");
    let text = "  Prefer blue, not red.\nBudget: $100  ";
    scope.set(
        StateNamespace::Input,
        "message".to_owned(),
        Some(Box::new(text.to_owned())),
    );
    let mut updates = StateUpdates::default();
    updates.set("unrelated".to_owned(), Some(Box::new(99_u64)));
    let mut proposal = TurnProposal::Advance { next: None, updates };
    step.finalize(&scope, &mut proposal).unwrap();
    let TurnProposal::Advance { next, updates } = proposal else {
        panic!("expected advance")
    };
    assert_eq!(next.unwrap().0, "done");
    assert_eq!(updates.get::<String>("message").unwrap(), text);
    assert!(updates.get::<u64>("unrelated").is_none());
    assert_eq!(scope.state().get::<String>("message").unwrap(), "");
}

#[test]
fn rejects_missing_wrongly_typed_input_and_restore() {
    let mut scope = scope();
    let step = TextInputStep::new("message", "Your message", "done");
    let TemplateSpec::Skip(mut proposal) = step.model_template(&scope) else {
        unreachable!()
    };
    assert!(step.finalize(&scope, &mut proposal).is_err());
    scope.set(StateNamespace::Input, "message".to_owned(), Some(Box::new(12_u64)));
    assert!(step.finalize(&scope, &mut proposal).is_err());
    scope.set(
        StateNamespace::Input,
        "message".to_owned(),
        Some(Box::new("text".to_owned())),
    );
    assert!(
        step.finalize(&scope, &mut TurnProposal::Restore { scope: "old".into() })
            .is_err()
    );
    assert!(scope.trace().entries.is_empty());
}
