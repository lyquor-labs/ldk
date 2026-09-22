# Text Input Step

`TextInputStep` collects a `String` text message and commits it to one declared State field.

```rust
use lyquid_flow::{Flow, State};
use text_input_step::TextInputStep;

let state = State::builder()
    .field("message-field-name", "Message Field Description", "Message Value".to_owned())
    .build()?;
let flow = Flow::builder("collect-goal")
    .entry("text-input")
    .exit("next-step")
    .step("text-input", TextInputStep::new("message-field-name", "Prompt Message", "next-step"))
    .build()?;
```

Bind these to a `Scope` and run it from the application's execution task. The application reads the pending `InputSpec`
from `scope.input_handle()` and submits a `String` using `offer_input(Box::new(message))`. The field must exist in State
with type `String`. Text is preserved as submitted; application-specific validation belongs to the caller.

## HTML text bar

`text_input_step::render_html(&spec)` renders an unstyled form containing a label, `<input type="text">`, and submit
button. Dynamic prompts and field names are HTML-escaped. Attach an application-owned submit handler, read the field's
value, and send it to the waiting Scope; the library does not embed JavaScript or assume an HTTP endpoint. Applications
with an existing design can render their own text field using the same specification.

## Dynamic prompts

Use `.with_prompt(|scope| ...)` when the prompt depends on runtime State rather than a fixed message supplied when the
Flow is built. The callback runs whenever the Step requests input and can read values written by earlier Steps from the
current Scope's committed State. This lets the same Step display different prompts on different visits without rebuilding
the Flow. Only the prompt text is dynamic; the destination State field remains the one configured for the Step.
