# Refinement Step example

This Step supports the [refinement loop Flow](../../../flows/refinement-loop-flow/README.md). Its State fields,
decision types, and model contract may be specific to that example. It demonstrates a domain implementation;
it is not intended to be a general-purpose refinement component with configurable bindings for every caller layout.

The native `Step` implementation owns its model template, State decoding, decision sanitization,
fixed successor, and Trace summary.

`refinement_step(next)` returns a `RefinementStep` that performs one model-driven refinement turn over a fixed,
non-empty candidate list. It reads a committed message, updates the goal and ranking, suggests an optional question,
and advances to one configured successor.

```rust
use lyquid_flow::Flow;
use refinement_step::{Candidate, DecisionRequest, initial_state, refinement_step};

let state = initial_state(DecisionRequest::new(
    "Prefer a compact option with offline support",
    vec![
        Candidate::new("a", "Compact; supports offline use"),
        Candidate::new("b", "Higher capacity; requires a connection"),
    ],
))?;
let flow = Flow::builder("refine-once")
    .entry("refine")
    .step("refine", refinement_step("show_results"))
    .exit("show_results")
    .build()?;
```

Run the Flow and State in a `Scope` with an application-owned `ModelConfig`. Provider selection and credentials stay
outside this crate. `refinement_step::model_turn_schema("show_results")` supplies an optional provider-neutral structured-output schema.

## State and composition

`Step::model_context` exposes the request and committed message as `context.request` and `context.message`.
The finalizer deserializes the proposed JSON decision into `DecisionState`, sanitizes the ranking and next
hint, writes the result as JSON, and produces the Trace summary. Core validates the final value against
the State declaration before committing it.

The preceding Step must provide at least one candidate or route elsewhere. The refinement Step checks this
precondition before calling the model. State initialization may use an empty placeholder while an earlier Step
collects candidates.

The model template sets `allow_restore` to `false`. Flow's response parser restricts model updates to the declared
decision field, and the typed decision schema requires a complete replacement.

`initial_state` (or `add_state_fields` for an existing builder) declares:

- `DECISION_REQUEST_STATE_FIELD`: immutable request and candidate facts, with unique, nonempty IDs.
- `REFINEMENT_INPUT_FIELD`: caller-owned `String`, initially seeded from the request.
- `DECISION_STATE_FIELD`: the complete `DecisionState` containing `goal`, `ranking`, and `question`.

Before another turn, an application uses a native Step with a [text InputSpec](../../inputs/text/README.md) to commit
the next message to `REFINEMENT_INPUT_FIELD`. The message may answer the suggested question or directly revise a requirement or preference.
The containing Flow owns the loop, input collection, and any selection or exit policy; this Step never waits for input.

## Model boundary

Only a complete decision update is accepted. Unknown and duplicate candidate IDs are removed; revised requirements may
re-admit IDs from the original list. Restore proposals and missing or malformed decisions fail without committing the
turn, leaving the committed message available for retry. Retry policy belongs to the caller.

Every successful turn uses the configured successor, even when the ranking becomes empty. The original candidate
list remains available for reconsideration on later turns. No candidates are retrieved or added.
