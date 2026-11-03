# Text InputSpec example

[input.rs](input.rs) builds a native `InputSpec` with one String field named `message` and a Send button.
[input.json](input.json) declares the equivalent UI and input schema and deserializes directly to `InputSpec`.
Both files describe only the form. The containing Step chooses how to save the submission and where to continue.

Load the JSON form into a native Step, then wrap it to copy the submitted message into State:

```rust
use lyquid_flow::{
    FlowError, InputSpec, Scope, StateNamespace, StateUpdates, Step, TemplateSpec,
    TraceSummary, TurnProposal,
};
use lyquid_structured_builder::{StructuredSpec, ValueSpec};

struct TextInput(InputSpec);

impl Step for TextInput {
    fn description(&self, _: bool) -> String {
        "Collect a text message".into()
    }

    fn input(&self, _: &Scope) -> Option<InputSpec> {
        Some(self.0.clone())
    }

    fn model_template(&self, _: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: Some("done".into()),
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, _: &Scope, _: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        Ok(TraceSummary::Summary("Received a text message".into()))
    }
}

let input: InputSpec = serde_json::from_str(include_str!("input.json"))?;
let step = StructuredSpec::builder()
    .state_updates(vec![(
        "message".into(),
        ValueSpec::reference(StateNamespace::Input, "message"),
    )])
    .build()
    .with(TextInput(input))?;
```

To use the Rust form in the same Step, construct `input` with:

```rust
#[path = "input.rs"]
mod text_input;

let input = text_input::input_spec()?;
```

Declare a String `message` State field and a `done` destination in the Flow. Rust-built and deserialized
specs deliver schema-validated JSON values. Core validates structured updates against destination State
declarations. The JSON loader also validates the UI graph and submit event.

Text is saved exactly, including whitespace and empty strings. Add `.non_blank()` to the Rust field
builder when the application requires nonblank input, and express the same constraint in its JSON schema.
