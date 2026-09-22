# Refinement Step

`RefinementStep` performs one model-driven refinement turn over a fixed, caller-provided candidate list. It reads a
committed message, updates the goal and ranking, suggests an optional question, and advances to one configured successor.

```rust
use lyquid_flow::Flow;
use refinement_step::{Candidate, DecisionRequest, RefinementStep, initial_state};

let state = initial_state(DecisionRequest::new(
    "Prefer a compact option with offline support",
    vec![
        Candidate::new("a", "Compact; supports offline use"),
        Candidate::new("b", "Higher capacity; requires a connection"),
    ],
))?;
let flow = Flow::builder("refine-once")
    .entry("refine")
    .step("refine", RefinementStep::new("show_results"))
    .exit("show_results")
    .build()?;
```

Run the Flow and State in a `Scope` with an application-owned `ModelConfig`. Provider selection and credentials stay
outside this crate. `step.model_turn_schema()` supplies an optional provider-neutral structured-output schema.

## State and composition

`initial_state` (or `add_state_fields` for an existing builder) declares:

- `DECISION_REQUEST_STATE_FIELD`: immutable request and candidate facts, with unique, nonempty IDs.
- `REFINEMENT_INPUT_FIELD`: caller-owned `String`, initially seeded from the request.
- `DECISION_STATE_FIELD`: the complete `DecisionState` containing `goal`, `ranking`, and `question`.

Before another turn, an application or [text-input step](../text-input-step/README.md) commits the next message to
`REFINEMENT_INPUT_FIELD`. The message may answer the suggested question or directly revise a requirement or preference.
The containing Flow owns the loop, input collection, and any selection or exit policy; this Step never waits for input.

## Model boundary

Only a complete decision update is accepted. Unknown and duplicate candidate IDs are removed; revised requirements may
re-admit IDs from the original list. Restore proposals and missing or malformed decisions fail without committing the
turn, leaving the committed message available for retry. Retry policy belongs to the caller.

Every successful turn uses the configured successor, even with no remaining candidates. An empty original list skips
the model and produces an empty decision. No candidates are retrieved or added.
