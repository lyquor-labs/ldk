//! Rust equivalent of the adjacent `input.json`, using Flow's native `InputSpec`.

use lyquid_flow::InputSpec;

/// Build the form with a String schema for its message.
pub fn input_spec() -> Result<InputSpec, lyquid_flow::Diagnostics> {
    let mut input = InputSpec::builder();
    let field = input.field::<String>("message", "Your message").text_input();
    let submit = input.submit("Send");
    let layout = input.ui().column(vec![field, submit]);
    input.finish(layout)
}
