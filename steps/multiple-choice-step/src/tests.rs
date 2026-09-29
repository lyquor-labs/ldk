use super::*;
use lyquid_flow::{AutoCheckpointConfig, Flow, State};
use lyquid_test::test;
use std::sync::Arc;

fn scope() -> Scope {
    Scope::new(
        Arc::new(
            Flow::builder("choice-test")
                .entry("choose")
                .step(
                    "choose",
                    MultipleChoiceStep::new("choice", "Pick", vec![Choice::new("a", "A", "done")]).unwrap(),
                )
                .exit("done")
                .build()
                .unwrap(),
        ),
        State::builder()
            .field("choice", "Chosen option", String::new())
            .field("parent", "Unrelated data", 7_u64)
            .build()
            .unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    )
}

#[test]
fn supports_any_number_of_options_and_shared_destinations_without_a_model() {
    for count in [1, 2, 5, 20] {
        let choices = (0..count)
            .map(|index| {
                Choice::new(
                    format!("id-{index}"),
                    format!("Option {index}"),
                    if index % 2 == 0 { "left" } else { "right" },
                )
            })
            .collect();
        let step = MultipleChoiceStep::new("choice", "Pick", choices).unwrap();
        for index in 0..count {
            let mut scope = scope();
            let id = format!("id-{index}");
            scope.set(StateNamespace::Input, "choice".to_owned(), Some(Box::new(id.clone())));
            let TemplateSpec::Skip(mut proposal) = step.model_template(&scope) else {
                panic!("choice called a model");
            };
            step.finalize(&scope, &mut proposal).unwrap();
            let TurnProposal::Advance { next, updates } = proposal else {
                unreachable!()
            };
            assert_eq!(next.unwrap().0, if index % 2 == 0 { "left" } else { "right" });
            assert_eq!(updates.get::<String>("choice"), Some(&id));
        }
    }
}

#[test]
fn rejects_empty_duplicate_and_invalid_menu_configuration() {
    for choices in [
        vec![],
        vec![Choice::new("a", "One", "x"), Choice::new("a", "Two", "y")],
        vec![Choice::new("", "Label", "x")],
        vec![Choice::new("id", " ", "x")],
        vec![Choice::new("id", "Label", "")],
    ] {
        assert!(MultipleChoiceStep::new("choice", "Pick", choices).is_err());
    }
}

#[test]
fn rejects_missing_wrongly_typed_input_unknown_ids_labels_and_routes() {
    let step = MultipleChoiceStep::new("choice", "Pick", vec![Choice::new("a", "Option A", "done")]).unwrap();
    let mut scope = scope();
    assert_eq!(
        step.input(&scope).unwrap().field_schema("choice").unwrap()["enum"][0],
        "a"
    );
    for value in [
        None,
        Some(Box::new(12_u64) as Box<dyn lyquid_flow::Value>),
        Some(Box::new("done".to_owned())),
        Some(Box::new("unknown".to_owned())),
        Some(Box::new("Option A".to_owned())),
    ] {
        scope.set(StateNamespace::Input, "choice".to_owned(), value);
        let TemplateSpec::Skip(mut proposal) = step.model_template(&scope) else {
            unreachable!()
        };
        assert!(step.finalize(&scope, &mut proposal).is_err());
        assert!(scope.trace().entries.is_empty());
        assert_eq!(scope.state().get::<String>("choice").unwrap(), "");
    }
}

#[test]
fn ignores_proposed_routes_and_unrelated_updates_and_rejects_restore() {
    let step = MultipleChoiceStep::new("choice", "Pick", vec![Choice::new("a", "A", "done")]).unwrap();
    let mut scope = scope();
    scope.set(
        StateNamespace::Input,
        "choice".to_owned(),
        Some(Box::new("a".to_owned())),
    );
    let mut updates = StateUpdates::default();
    updates.set("parent".to_owned(), Some(Box::new(99_u64)));
    let mut proposal = TurnProposal::Advance {
        next: Some("injected".into()),
        updates,
    };
    step.finalize(&scope, &mut proposal).unwrap();
    let TurnProposal::Advance { next, updates } = proposal else {
        unreachable!()
    };
    assert_eq!(next.unwrap().0, "done");
    assert!(updates.get::<u64>("parent").is_none());
    assert!(
        step.finalize(
            &scope,
            &mut TurnProposal::Restore {
                scope: "checkpoint".into()
            }
        )
        .is_err()
    );
}

#[test]
fn publishes_dynamic_prompt() {
    let step = MultipleChoiceStep::new(
        "choice",
        "Pick",
        vec![
            Choice::new("a", "Option A", "left"),
            Choice::new("b", "Option B", "right"),
        ],
    )
    .unwrap()
    .with_prompt(|scope| format!("Round {}", scope.state().get::<u64>("parent").unwrap()));
    let spec = step.input(&scope()).unwrap();
    assert_eq!(spec.field_schema("choice").unwrap()["title"], "Round 7");
}
