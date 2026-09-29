# Refinement Loop Flow

`RefinementLoopConfig` builds a loop over a fixed, caller-provided candidate list using the
[refinement](../../steps/refinement-step/README.md) and [text-input](../../steps/text-input-step/README.md) steps.
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

Configuring exits adds a [multiple-choice step](../../steps/multiple-choice-step/README.md) with `refine` plus your
options. There are no built-in finish, cancel, or restart actions. A mounted child Flow requires at least one exit;
the exit-free default runs standalone.

```text
   refine <----------------------------------+
     |                                       |
     v                                       |
   choose -- refine --> text feedback -------+
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
- `CHOICE_STATE_FIELD`: `refine` or a configured exit ID; render IDs and labels from `config.choice_options()`.

With no exits, `choice_options()` is empty and the choice State field is omitted. Otherwise, options are ordered as
`refine`, then your exits. `DECISION_STATE_FIELD` holds the `DecisionState`: goal, ranking, and hint.

Use blocking `Scope::advance()` or cooperative `Scope::run_until_input()`. Both publish requests through
`InputHandle`; submit the complete field object through `submit_input()`. For cooperative
execution, call `run_until_input()` again after acceptance. Step IDs and constructors are internal; compose the step
crates directly for other graphs.

Input commits separately from refinement. A failed model turn preserves the last decision and leaves the submitted
message available for retry. Invalid choices do not commit a route. Retry and abandoned-session cleanup policies
belong to the application.
