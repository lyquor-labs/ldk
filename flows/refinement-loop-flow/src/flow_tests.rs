use super::*;
use lyquid_test::test;
use refinement_step::Candidate;

// Keep the real input Step and graph destinations; model behavior is covered by composition tests.
fn input_flow(config: &RefinementLoopConfig) -> Flow {
    let mut builder = Flow::builder("input-contract")
        .entry(CHOICE_STEP)
        .step(CHOICE_STEP, config.choice_step().unwrap())
        .step(
            REFINE_STEP,
            StructuredStepBuilder::new().next(CHOICE_STEP).build().unwrap(),
        );
    for exit in &config.exits {
        builder = builder.exit(exit.id.as_str());
    }
    builder.build().unwrap()
}

#[test]
fn combined_refinement() {
    use lyquid_flow::{AutoCheckpointConfig, service::FlowService};
    use serde_json::json;
    use std::sync::Arc;

    let config = RefinementLoopConfig::new(vec![ExitChoice::new("done", "Done")])
        .unwrap()
        .nonblank();
    let service = FlowService::new();
    let id = service
        .register(Scope::new(
            Arc::new(input_flow(&config)),
            config.initial_state(DecisionRequest::new("Initial", vec![])).unwrap(),
            AutoCheckpointConfig::Disabled,
            None,
        ))
        .unwrap();
    let client = service.resolve(&id).unwrap();
    client.run().unwrap();
    let input = client.read().unwrap().input.unwrap();
    assert!(input.spec["schema"]["properties"].get(REFINEMENT_INPUT_FIELD).is_some());
    assert!(
        !input.spec["ui"]["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["component"] == "ChoicePicker")
    );
    for values in [
        json!({CHOICE_STATE_FIELD: "refine"}),
        json!({CHOICE_STATE_FIELD: "refine", REFINEMENT_INPUT_FIELD: " \n "}),
        json!({CHOICE_STATE_FIELD: "unknown"}),
    ] {
        assert!(client.submit(&input.request_id, &values.to_string()).is_err());
        assert_eq!(client.read().unwrap().input.unwrap().request_id, input.request_id);
    }
    let values = json!({CHOICE_STATE_FIELD: "refine", REFINEMENT_INPUT_FIELD: "More portable"}).to_string();
    client.submit(&input.request_id, &values).unwrap();
    assert!(client.submit(&input.request_id, &values).is_err());
    client.run().unwrap();
    let next = client.read().unwrap();
    assert_eq!(next.step.id.0, CHOICE_STEP);
    let input = next.input.unwrap();
    client
        .submit(&input.request_id, &json!({CHOICE_STATE_FIELD: "done"}).to_string())
        .unwrap();
    client.run().unwrap();
    assert!(client.read().unwrap().input.is_none());
}

#[test]
fn unavailable_actions() {
    use lyquid_flow::AutoCheckpointConfig;
    use serde_json::json;
    use std::sync::Arc;

    let config = RefinementLoopConfig::new(vec![ExitChoice::new("done", "Done")])
        .unwrap()
        .with_available(|_, choice| choice.id != "done");
    let mut scope = Scope::new(
        Arc::new(input_flow(&config)),
        config.initial_state(DecisionRequest::new("Initial", vec![])).unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    let (spec, _) = scope.run_until_input().unwrap().unwrap();
    assert!(spec.decode_values(&json!({CHOICE_STATE_FIELD: "done"})).is_err());
    assert!(
        !spec.ui().data()["content"]
            .as_object()
            .unwrap()
            .values()
            .any(|value| value == "Done")
    );
}

#[test]
fn refine_stays_available() {
    use lyquid_flow::AutoCheckpointConfig;
    use serde_json::json;
    use std::sync::Arc;

    let config = RefinementLoopConfig::new(vec![ExitChoice::new("done", "Done")])
        .unwrap()
        .with_available(|_, _| false)
        .nonblank();
    let mut scope = Scope::new(
        Arc::new(input_flow(&config)),
        config.initial_state(DecisionRequest::new("Initial", vec![])).unwrap(),
        AutoCheckpointConfig::Disabled,
        None,
    );
    let (spec, _) = scope.run_until_input().unwrap().unwrap();
    assert_eq!(
        spec.schema()["properties"][CHOICE_STATE_FIELD]["enum"],
        json!([CONTINUE_CHOICE])
    );
    let input = scope.input_handle();
    for values in [
        json!({CHOICE_STATE_FIELD: "done"}),
        json!({CHOICE_STATE_FIELD: CONTINUE_CHOICE}),
        json!({CHOICE_STATE_FIELD: CONTINUE_CHOICE, REFINEMENT_INPUT_FIELD: " \n "}),
    ] {
        assert!(input.submit_input(&values.to_string()).is_err());
    }
    input
        .submit_input(
            &json!({CHOICE_STATE_FIELD: CONTINUE_CHOICE, REFINEMENT_INPUT_FIELD: "More portable"}).to_string(),
        )
        .unwrap();
    scope.advance().unwrap();
    assert_eq!(scope.current_step().0, REFINE_STEP);
    assert_eq!(
        scope.state().get::<String>(CHOICE_STATE_FIELD).unwrap(),
        CONTINUE_CHOICE
    );
    assert_eq!(
        scope.state().get::<String>(REFINEMENT_INPUT_FIELD).unwrap(),
        "More portable"
    );
    assert!(scope.run_until_input().unwrap().is_some());
}

#[test]
fn default_loop_has_no_choice_step_menu_or_choice_state() {
    for config in [
        RefinementLoopConfig::default(),
        RefinementLoopConfig::new(vec![]).unwrap(),
    ] {
        assert!(config.choice_options().is_empty());
        assert!(config.choice_step().is_none());
        assert_eq!(config.model_turn_schema()["properties"]["next"]["enum"][0], INPUT_STEP);
        let state = config
            .initial_state(DecisionRequest::new("Initial goal", vec![]))
            .unwrap();
        assert!(state.get::<String>(CHOICE_STATE_FIELD).is_none());
        assert_eq!(state.get::<String>(REFINEMENT_INPUT_FIELD).unwrap(), "Initial goal");
    }
}

#[test]
fn configurable_exits_add_continue_then_preserve_caller_menu_order() {
    for count in [1, 2, 8] {
        let exits = (0..count)
            .map(|index| ExitChoice::new(format!("exit-{index}"), format!("Action {index}")))
            .collect::<Vec<_>>();
        let config = RefinementLoopConfig::new(exits.clone()).unwrap();
        let choices = config.choice_options();
        assert_eq!(choices.len(), count + 1);
        assert_eq!(choices[0].id, CONTINUE_CHOICE);
        for (choice, exit) in choices[1..].iter().zip(exits) {
            assert_eq!(choice.id, exit.id);
            assert_eq!(choice.label, exit.label);
        }
        assert!(config.choice_step().is_some());
        assert_eq!(config.model_turn_schema()["properties"]["next"]["enum"][0], CHOICE_STEP);
        let state = config.initial_state(DecisionRequest::new("", vec![])).unwrap();
        assert_eq!(state.get::<String>(CHOICE_STATE_FIELD).unwrap(), "");
    }
}

#[test]
fn rejects_blank_duplicate_and_reserved_exit_configuration() {
    for exits in [
        vec![ExitChoice::new("", "Label")],
        vec![ExitChoice::new(" \n ", "Label")],
        vec![ExitChoice::new("done", " ")],
        vec![ExitChoice::new("done", "One"), ExitChoice::new("done", "Two")],
        vec![ExitChoice::new(CONTINUE_CHOICE, "Override continue")],
        vec![ExitChoice::new(INPUT_STEP, "Override input")],
        vec![ExitChoice::new(CHOICE_STEP, "Override choice")],
    ] {
        assert!(RefinementLoopConfig::new(exits).is_err());
    }
}

#[test]
fn state_initialization_reuses_refinement_validation_and_preserves_parent_fields() {
    for config in [
        RefinementLoopConfig::default(),
        RefinementLoopConfig::new(vec![ExitChoice::new("done", "Done")]).unwrap(),
    ] {
        assert!(
            config
                .initial_state(DecisionRequest::new(
                    "",
                    vec![Candidate::new("a", "One"), Candidate::new("a", "Two")],
                ))
                .is_err()
        );
        let state = config
            .add_state_fields(
                State::builder().field("parent", "Parent-owned data", 7_u64),
                DecisionRequest::new("Initial goal", vec![Candidate::new("a", "One")]),
            )
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(state.get::<u64>("parent"), Some(&7));
        assert_eq!(state.get::<String>(REFINEMENT_INPUT_FIELD).unwrap(), "Initial goal");
    }
}
