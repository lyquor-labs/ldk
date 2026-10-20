# Structured Step builder

`lyquid-structured-step` provides `StructuredStepBuilder` to assemble an ordinary
[lyquid-flow](../lyquid-flow/README.md) Step from reusable input, model, and finalization components.
The built `StructuredStep` implements the core `Step` contract. "Structured" describes this Rust
authoring layer; declarative configuration is a separate capability, and opaque Rust callbacks can
run natively even when configuration export is unavailable.
Configure behavior and data wiring in one chain instead of writing a custom Step implementation:

```rust
let step = StructuredStepBuilder::new()
    .with_input(input_spec)
    .with_model(model_template)
    .action(action1)
    .action(formatter)
    .action(action2)
    .next("done")
    .summary("Step completed")
    .build()?;
```

Every built Step follows **input → model → finalize → validate/commit**. Omit `with_input`,
`with_model`, or all `action` calls to skip that work automatically; no bypass flags are needed.
Pass an `InputSpec` built with Flow's field/layout builders or loaded from JSON directly to `with_input`,
and a `ModelTemplate` to `with_model`. Reusable input helpers are optional. Finalization
actions are ordinary Rust functions, including formatters, appended with `.action(...)`. They run in
declaration order and stop at the first error. `build()` returns an ordinary Step; Flow owns execution,
State, checkpoints, validation, and the atomic commit.

Routing owns model restore permission: `.next(...)`, `.complete()`, and `.route_by(...)` exclude
restores from the model contract and reject restore proposals. `.proposed_next()` permits them when
the model template allows restoration. Explicit application calls to `Scope::restore` remain available.

The optional [JSON formatter action](../steps/actions/json_formatter/README.md) supplies JSON parsing
and schema validation through the same action API. See the [usage guide and API reference](GUIDE.md)
for Rust APIs, saved JSON wiring, shared action inputs, examples, and failure behavior.

`StructuredStepBuilder` and the built `StructuredStep` expose `.to_json()` for configuration export.
Use `.action_with_config(name, settings, callback)` to retain an explicit callback reference alongside
its native Rust implementation. Export never executes callbacks and does not change typed State or
input codecs. Opaque callbacks still run natively but produce an export error. JSON execution belongs
to the future headless runner; there is no action registry or JSON-to-Step loader here.

Declare reusable data with `.data::<T>(name)` and `.result::<T>()`. The same declarations drive
validation, `data_contract()` inspection, and schemas in `.to_json()`. Bind the argument names to
caller fields using `.bind_data(...)` or `.bind_state(...)`; required arguments must be bound before
native `build()`. Input factories and actions can use bound data without knowing caller field names.
Static input bindings reject known field/path errors and incompatible declared JSON types during
build and export. Result bindings and routing reject known impossible paths; routes must be able to
produce strings. Dynamic schemas and value-dependent validation remain runtime checks.

Model prompts, actions, and summaries can use the prepared `context.<argument>`, including nested
fields. Native model templates also retain `state`, interactive `input`, `trace`, and `step`.
See the [data-contract guide](GUIDE.md#declare-data-contracts) for phase availability and logical model outputs.
These contracts support the [Flow graph authoring work](https://github.com/lyquor-labs/lyquor/issues/1656).
