//! Rust equivalent of the adjacent `input.json`, using Flow's native `InputSpec`.

use lyquid_flow::InputSpec;

/// Build the native form with String decoders for Rust authoring.
pub fn input_spec() -> Result<InputSpec, String> {
    let mut input = InputSpec::builder();
    let field = input.field("message", "Your message", String::new()).text_input();
    let submit = input.submit("Send");
    let layout = input.ui().column(vec![field, submit]);
    input.finish(layout)
}
