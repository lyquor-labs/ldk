# Refinement Loop Flow example

This Flow demonstrates composition and configuration for candidate refinement. Its
[refinement Step](../../steps/examples/refinement-step/README.md) may use State fields and decision contracts
specific to this loop. The LDK focuses on helping authors configure their own Steps and Flows from reusable
actions; this example does not need to become a general-purpose workflow component.

`RefinementLoopConfig` builds a loop over a fixed, caller-provided candidate list using the
[refinement Step](../../steps/examples/refinement-step/README.md) and native
[text InputSpec](../../steps/inputs/text/README.md) composed with `StepBuilder`.
Each message updates the goal, ranking, and next hint. Users may answer the hint or state any requirement directly.

The default loop has no menu or exits:

```text
initial goal
     |
     v
   refine <--------------------+
     |                         |
     +--> text feedback -------+
```

An empty ranking does not end the loop. Users can relax requirements to re-admit candidates from the original list.
Retrieval, selection, model configuration, UI, and session lifetime belong to the application.
The preceding action must supply a non-empty original candidate list before entering refinement; empty retrieval
results must be handled by the application. An empty State placeholder is allowed before that action runs.

## Use

```rust
use refinement_loop_flow::{Candidate, DecisionRequest, RefinementLoopConfig};

let config = RefinementLoopConfig::default();
let state = config.initial_state(DecisionRequest::new(
    "Prefer a compact option with offline support",
    vec![
        Candidate::new("a", "Compact; supports offline use"),
        Candidate::new("b", "Higher capacity; requires a connection"),
    ],
))?;
let flow = config.flow();
```

Bind the Flow and State to a `Scope` with an application-owned `ModelConfig`. Use the same configuration for State,
Flow, UI choices, and `model_turn_schema()`. Use `add_state_fields()` to extend an existing State builder.

`flow()` starts with the supplied goal. To collect the goal first, use `flow_from_input()` and an empty `user_request`.

## Exit choices and parent Flows

Configuring exits adds one combined input Step: a feedback field, a **Refine** button, and buttons for your
exit options. There are no built-in finish, cancel, or restart actions. A mounted child Flow requires at least one exit;
the exit-free default runs standalone.

```text
   refine <----------------------------------+
     |                                       |
     v                                       |
   feedback + action -- Refine --------------+
     |
     +-- configured exit --> parent
```

```rust
use lyquid_flow::{ExitTransitions, TraceMode};
use refinement_loop_flow::{ExitChoice, RefinementLoopConfig};

let config = RefinementLoopConfig::new(vec![
    ExitChoice::new("done", "Use these results"),
    ExitChoice::new("restart", "Request different candidates"),
])?;

let exits = ExitTransitions::new()
    .transition("done", "select_candidate")?
    .transition("restart", "collect_feedback")?;
let parent = parent_builder
    .flow("refine_options", config.flow(), exits, TraceMode::Expanded);
```

Each option ID is its submitted value and named Flow exit. IDs and labels must be nonblank; IDs must be unique and
cannot be `input`, `refine`, or `choose`. Map every exit to a declared parent step or exit through `ExitTransitions`.
Build the parent State with this configuration's `add_state_fields()`.

Exits do not call the model or collect feedback. In this example, the parent supplies `select_candidate` and
`collect_feedback`; it can read the committed decision, collect restart feedback, retrieve new candidates, and
initialize another refinement run. See [shopping-assistant](../../lyquid-examples/shopping-assistant/README.md).

## Input and State

The application displays each `InputSpec` and submits a JSON object keyed by its field name. Use `field_schema()` to distinguish:

- `REFINEMENT_INPUT_FIELD`: the initial goal or next refinement message.
- `CHOICE_STATE_FIELD`: `refine` or a configured exit ID, supplied by the clicked button.

With exits, submit `CHOICE_STATE_FIELD` and `REFINEMENT_INPUT_FIELD` together to refine. Exit actions require only
`CHOICE_STATE_FIELD`; they do not overwrite committed feedback. Button values are declared in the native A2UI
submit event, validated by the same InputSpec, and do not create a second input round. The field prompt contains
the current hint, while candidate presentation belongs in the application's ViewSpec.

With no exits, `choice_options()` is empty and the choice State field is omitted. Otherwise, options are ordered as
`refine`, then your exits. The method returns `ExitChoice` values containing only IDs and labels; routing stays
inside the loop. `DECISION_STATE_FIELD` holds the `DecisionState`: goal, ranking, and hint.

Use blocking `Scope::advance()` or cooperative `Scope::run_until_input()`. Both publish requests through
`InputHandle`; submit the complete field object through `submit_input()`. For cooperative
execution, call `run_until_input()` again after acceptance. Step IDs and constructors are internal; compose
`InputSpec` with `StepBuilder` and the refinement Step directly for other graphs.

Input commits separately from refinement. A failed model turn preserves the last decision and leaves the submitted
message available for retry. Invalid choices do not commit a route. Retry and abandoned-session cleanup policies
belong to the application.

Applications can opt into `RefinementLoopConfig::nonblank()` for required feedback and
`with_available(predicate)` for state-dependent exit availability. The built-in **Refine** action always remains
available, even when the predicate rejects every choice. These constraints are exported in InputSpec and enforced
for HTTP as well as direct submissions; exit wiring remains fixed.
