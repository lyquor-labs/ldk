# Multiple Choice Step

`MultipleChoiceStep` collects one option ID, commits it to a `String` State field, and follows its configured destination.
Option IDs, labels, and destinations are fixed when the Step is built; State-driven choices are not supported.

```rust
use lyquid_flow::{Flow, State};
use multiple_choice_step::{Choice, MultipleChoiceStep};

let state = State::builder()
    .field("action", "Latest chosen action ID", String::new())
    .build()?;
let choose = MultipleChoiceStep::new("action", "What next?", vec![
    Choice::new("edit", "Edit the details", "text_input"),
    Choice::new("compare", "Compare options", "compare"),
    Choice::new("finish", "Finish", "done"),
])?;
let flow = Flow::builder("decision")
    .entry("choose")
    .step("choose", choose)
    .step("text_input", text_input_step)
    .step("compare", comparison_step)
    .exit("done")
    .build()?;
```

Keep `scope.input_handle()` before running the Flow. Read its pending `input_spec()` and submit a complete object,
for example `handle.submit_input(&serde_json::json!({"action": choice_id}).to_string())`.
The named State field must have type `String`; unknown IDs fail input validation while the request remains pending.
Provide at least one option with a unique ID. IDs, labels, and destinations must be nonempty; multiple options may
share a destination.

## Dynamic prompts

Use `.with_prompt(|scope| ...)` when the prompt depends on State produced by earlier Steps. Only the prompt text changes;
the choices and their destinations remain fixed.
