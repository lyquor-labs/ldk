# InputSpec examples

These examples declare input forms using Flow's native `InputSpec`:

- [Text](text/README.md): one String field, preserving the submitted text exactly.
- [Multiple choice](multiple-choice/README.md): one String field constrained to declared choice IDs.

Each folder pairs an `input.rs` builder with a directly deserializable `input.json` containing
the equivalent UI and validation schema. Attach either form with `StructuredStepBuilder::with_input`.
The containing Step owns bindings, routing, and summaries; the Flow owns State and destinations.

These forms replace the `text-input-step` and `multiple-choice-step` helper crates. For a prompt
derived from committed State, build the form in `StructuredStepBuilder::with_input_factory`; keep the factory
pure because StructuredStepBuilder also calls it during preflight and finalization.

The [composition tests](tests/mod.rs) compare the schemas
and exercise both forms with the same Step wiring, including invalid choices and exact text preservation.

These tests are compiled into `lyquid-structured-step`'s guest test artifact so the normal LDK workspace
test run discovers them. The examples do not need a separate Cargo crate or test runner.
