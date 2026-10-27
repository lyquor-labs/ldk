# Multiple-choice InputSpec example

[input.rs](input.rs) builds a native `InputSpec` with one String field named `choice` and a Choose button.
[input.json](input.json) declares the equivalent UI and input schema and deserializes directly to `InputSpec`.
Both files describe only the form. The containing Step chooses how to save the submission and where to continue.

Load the JSON form into a native Step. Its finalizer routes the choice; the structured wrapper saves it:

```rust
use lyquid_flow::{
    FlowError, InputSpec, Scope, StateNamespace, StateUpdates, Step, TemplateSpec,
    TraceSummary, TurnProposal,
};
use lyquid_structured_builder::{StructuredSpec, ValueSource};

struct ChoiceInput(InputSpec);

impl Step for ChoiceInput {
    fn description(&self, _: bool) -> String {
        "Choose an action".into()
    }

    fn input(&self, _: &Scope) -> Option<InputSpec> {
        Some(self.0.clone())
    }

    fn model_template(&self, _: &Scope) -> TemplateSpec {
        TemplateSpec::Skip(TurnProposal::Advance {
            next: None,
            updates: StateUpdates::default(),
        })
    }

    fn finalize(&self, scope: &Scope, proposal: &mut TurnProposal) -> Result<TraceSummary, FlowError> {
        let TurnProposal::Advance { next, .. } = proposal else {
            return Err("choice input requires an advance proposal".into());
        };
        let choice = scope.get(StateNamespace::Input, "choice")
            .and_then(serde_json::Value::as_str).ok_or("missing choice")?;
        *next = Some(match choice {
            "edit" => "text_input".into(),
            "finish" => "done".into(),
            _ => return Err("invalid choice".into()),
        });
        Ok(TraceSummary::Summary(format!("Chose {choice}")))
    }
}

let input: InputSpec = serde_json::from_str(include_str!("input.json"))?;
let step = StructuredSpec::builder()
    .state_updates(vec![(
        "choice".into(),
        ValueSource::reference(StateNamespace::Input, "choice"),
    )])
    .build()
    .with(ChoiceInput(input))?;
```

To use the Rust form in the same Step, construct `input` with:

```rust
#[path = "input.rs"]
mod multiple_choice;

let input = multiple_choice::input_spec()?;
```

Declare a String `choice` State field and `text_input`/`done` destinations in the Flow. Rust-built and
deserialized specs deliver schema-validated JSON values. The finalizer reads the selected string through
`Value::as_str`; Core validates structured updates against destination State declarations before commitment.
The JSON loader also validates the UI graph and submit event.

The form submits `edit` or `finish`; labels are presentation only. Unknown IDs, labels submitted as IDs,
and values of the wrong type are rejected while input remains pending. Routing belongs to the native finalizer above.
