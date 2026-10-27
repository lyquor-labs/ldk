//! Rust equivalent of the adjacent `input.json`, using Flow's native `InputSpec`.

use lyquid_flow::InputSpec;

/// Build the form with a String schema for its choice.
pub fn input_spec() -> Result<InputSpec, lyquid_flow::Diagnostics> {
    let mut input = InputSpec::builder();
    let field = input
        .field::<String>("choice", "What next?")
        .choices([("edit", "Edit the details"), ("finish", "Finish")])
        .select_one();
    let submit = input.submit("Choose");
    let layout = input.ui().column(vec![field, submit]);
    input.finish(layout)
}
