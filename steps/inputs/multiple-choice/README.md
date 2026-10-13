# Multiple-choice InputSpec example

[input.rs](input.rs) builds a native `InputSpec` with one String field named `choice` and a Choose button.
[input.json](input.json) declares the equivalent UI and input schema and deserializes directly to `InputSpec`.
Both files describe only the form. The containing Step chooses how to save the submission and where to continue.

Load the JSON form and attach it directly:

```rust
use lyquid_configured_step::{StepBuilder, ValueSource};
use lyquid_flow::InputSpec;

let input: InputSpec = serde_json::from_str(include_str!("input.json"))?;
let step = StepBuilder::new()
    .description("Choose an action")
    .with_input(input)
    .bind_input("choice", "choice")
    .update_from("choice", ValueSource::Input { name: "choice".into() })
    .route_by("/choice", [("edit", "text_input"), ("finish", "done")])
    .summary("Chose {{ result.choice }}")
    .build()?;
```

To use the Rust form in the same Step, construct `input` with:

```rust
#[path = "input.rs"]
mod multiple_choice;

let input = multiple_choice::input_spec()?;
```

Declare a String `choice` State field and `text_input`/`done` destinations in the Flow. Rust-built specs
retain String decoders; deserialized specs use schema-validated JSON decoders, and Step bindings decode
their values through the destination State codecs. The JSON loader also validates the UI graph and submit event.

The form submits `edit` or `finish`; labels are presentation only. Unknown IDs, labels submitted as IDs,
and values of the wrong type are rejected while input remains pending. Routing belongs to the Step wiring above.
