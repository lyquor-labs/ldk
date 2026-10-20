# Text InputSpec example

[input.rs](input.rs) builds a native `InputSpec` with one String field named `message` and a Send button.
[input.json](input.json) declares the equivalent UI and input schema and deserializes directly to `InputSpec`.
Both files describe only the form. The containing Step chooses how to save the submission and where to continue.

Load the JSON form and attach it directly:

```rust
use lyquid_structured_step::{StructuredStepBuilder, ValueSource};
use lyquid_flow::InputSpec;

let input: InputSpec = serde_json::from_str(include_str!("input.json"))?;
let step = StructuredStepBuilder::new()
    .description("Collect a text message")
    .with_input(input)
    .update_from("message", ValueSource::Input { name: "message".into() })
    .next("done")
    .summary("Received a text message")
    .build()?;
```

To use the Rust form in the same Step, construct `input` with:

```rust
#[path = "input.rs"]
mod text_input;

let input = text_input::input_spec()?;
```

Declare a String `message` State field and a `done` destination in the Flow. Rust-built specs retain
String decoders; deserialized specs use schema-validated JSON decoders, and Step bindings decode their
values through the destination State codecs. The JSON loader also validates the UI graph and submit event.

Text is saved exactly, including whitespace and empty strings. Add `.non_blank()` to the Rust field
builder when the application requires nonblank input, and express the same constraint in its JSON schema.
