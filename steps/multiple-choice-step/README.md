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
let choices = choose.choices().to_vec(); // Retain for rendering after the Flow owns the Step.
let flow = Flow::builder("decision")
    .entry("choose")
    .step("choose", choose)
    .step("text_input", text_input_step)
    .step("compare", comparison_step)
    .exit("done")
    .build()?;
```

Keep `scope.input_handle()` before running the Flow. Read its pending `input_spec()` and submit an option ID as a `String`
using `offer_input(Box::new(choice_id))`. The named State field must have type `String`; unknown IDs reject the turn without
committing changes. Provide at least one option with a unique ID. IDs, labels, and destinations must be nonempty; multiple
options may share a destination.

## HTML choice buttons

`multiple_choice_step::render_html(&spec, &choices)` renders escaped HTML buttons using the pending input contract and
the fixed choices retained above. It needs no access to the running Scope or Step. Applications own styling, handlers,
and transport; each button's value is the selected ID. The input prompt also lists IDs and labels for terminal clients.

## Dynamic prompts

Use `.with_prompt(|scope| ...)` when the prompt depends on State produced by earlier Steps. Only the prompt text changes;
the choices and their destinations remain fixed.
