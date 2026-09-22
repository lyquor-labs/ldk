use std::sync::Arc;

use crate::{DECISION_STATE_FIELD, DecisionRequest, DecisionState, RefinementStep, add_state_fields};
use lyquid_flow::{AutoCheckpointConfig, ExitTransitions, Flow, Scope, State, TraceMode, TraceSummary};
use lyquid_test::test;

#[test]
fn mounted_refinement_rejoins_the_parent_without_collecting_input_or_calling_a_model() {
    let child = Flow::builder("refine-once")
        .entry("refine")
        .step("refine", RefinementStep::new("result"))
        .exit("result")
        .build()
        .unwrap();
    let parent = Flow::builder("parent")
        .entry("choose")
        .flow(
            "choose",
            child,
            ExitTransitions::new().transition("result", "done").unwrap(),
            TraceMode::Expanded,
        )
        .exit("done")
        .build()
        .unwrap();
    let state = add_state_fields(
        State::builder().field("parent", "Parent-owned data", 7_u64),
        DecisionRequest::new("Choose an option", Vec::new()),
    )
    .unwrap()
    .build()
    .unwrap();
    let mut scope = Scope::new(Arc::new(parent), state, AutoCheckpointConfig::Disabled, None);

    scope.advance().unwrap();

    assert!(scope.is_finished());
    assert_eq!(scope.current_step().0, "done");
    assert_eq!(scope.state().get::<u64>("parent"), Some(&7));
    assert_eq!(
        scope.state().get::<DecisionState>(DECISION_STATE_FIELD),
        Some(&DecisionState::default())
    );
    assert!(scope.input_handle().input_spec().is_none());
    assert_eq!(scope.trace().entries.len(), 1);
    let TraceSummary::SubFlow(child_trace) = &scope.trace().entries[0].summary else {
        panic!("expanded composition should retain the child Trace");
    };
    assert_eq!(child_trace.entries.len(), 1);
}
