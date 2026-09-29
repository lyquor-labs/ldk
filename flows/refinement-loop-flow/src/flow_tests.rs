use super::*;
use lyquid_test::test;
use refinement_step::Candidate;

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
        assert_eq!(choices[0].next.0, INPUT_STEP);
        for (choice, exit) in choices[1..].iter().zip(exits) {
            assert_eq!(choice.id, exit.id);
            assert_eq!(choice.label, exit.label);
            assert_eq!(choice.next.0, exit.id);
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
