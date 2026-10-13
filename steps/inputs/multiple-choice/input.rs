//! Rust equivalent of the adjacent `input.json`, using Flow's native `InputSpec`.

use lyquid_flow::InputSpec;

/// Build the native form with String decoders for Rust authoring.
pub fn input_spec() -> Result<InputSpec, String> {
    let mut input = InputSpec::builder();
    let field = input
        .field("choice", "What next?", String::new())
        .choices([("edit", "Edit the details"), ("finish", "Finish")])
        .select_one();
    let submit = input.submit("Choose");
    let layout = input.ui().column(vec![field, submit]);
    input.finish(layout)
}
