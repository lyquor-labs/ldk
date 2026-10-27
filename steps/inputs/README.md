# InputSpec examples

These examples declare input forms using Flow's native `InputSpec`:

- [Text](text/README.md): one String field, preserving the submitted text exactly.
- [Multiple choice](multiple-choice/README.md): one String field constrained to declared choice IDs.

Each folder pairs an `input.rs` builder with a directly deserializable `input.json` containing
the equivalent UI and validation schema. A native `Step` owns the form and returns it from `Step::input`.
The Step also owns routing and summaries; the Flow owns State and destinations.

Wrap the Step with [`StructuredSpec`](../../lyquid-structured-builder/README.md) to copy submitted fields
into State using `ValueSource::reference(StateNamespace::Input, field)`.
Choice-dependent routing belongs in the native `Step::finalize`.

For a prompt derived from committed State, build the form in `Step::input` using its `Scope` argument.
These example forms do not require a separate Cargo crate.
