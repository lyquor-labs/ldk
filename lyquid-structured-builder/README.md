# Structured Builder

`lyquid-structured-builder` adds State updates and next-Step selection to core
[`Step`](../lyquid-flow/README.md) objects.

`StructuredSpec` contains only `state_updates` and `next`. Its `typed-builder`-derived
builder sets each whole field once, in any order; `.build()` returns the spec. Use `.with(existing_step)`
to validate it and wrap an existing ordinary Step. The existing
Step's model contract incorporates the structured rules. Its finalizer runs before
structured updates revise the uncommitted result.
Descriptions, input forms, model goals and summaries remain in the original Step.
The design's Inputs/Output declarations and Next parameters are not implemented in this version.
In this example, `existing_step` supplies a model template for the structured model rules.

```rust
use lyquid_flow::{BuildError, StateNamespace, Step};
use lyquid_structured_builder::{NextCase, NextStep, StructuredSpec, StructuredStep, ValueSource};

fn assess(existing_step: impl Step + 'static) -> Result<StructuredStep, BuildError> {
    StructuredSpec::builder()
        .state_updates(vec![
            ("status".into(), ValueSource::constant("assessed")),
            ("previous_count".into(), ValueSource::reference(StateNamespace::Default, "count")),
            ("count".into(), ValueSource::model("Derive the count from {{ state.request }}")),
        ])
        .next(NextStep {
            steps: vec![
                NextCase { next: Some("approve".into()), description: "The request meets the requirements".into() },
                NextCase { next: Some("reject".into()), description: "The request does not meet the requirements".into() },
            ],
        })
        .build()
        .with(existing_step)
}
```

Register the wrapped Step with `Flow::builder("name").step(id, step)`.
`.with(...)` does not support wrapping an entire Flow. Mount child Flows with Core's
`.flow(...)`; their internal Steps can use the same wrappers.
Core owns final validation and commit.

The spec also supports direct struct construction and serde JSON serialization:

```rust
let spec = StructuredSpec {
    state_updates: vec![("reviewed".into(), ValueSource::constant(true))],
    ..Default::default()
};
let json = serde_json::to_string(&spec)?;
let restored: StructuredSpec = serde_json::from_str(&json)?;
let step = restored.with(existing_step)?;
```

JSON stores only the structured rules; the existing Step is supplied by Rust code.

## Value sources

Set `state_updates` to a list of `(field, source)` pairs.
`field` names a variable declared in the current Scope's State. `source` is one of
three `ValueSource` variants:

- `Constant { value }`: a fixed JSON value checked against the destination State's Type declaration.
  `ValueSource::constant(value)` constructs this variant.
- `State { namespace, field }`: reads the value of a field in that namespace.
  `ValueSource::reference(namespace, field)` constructs this variant.
- `Model { description }`: instructions describing when to change the field and what
  its replacement should contain. `ValueSource::model(description)` constructs this variant.

Structured references and model criteria read this turn's current State
before commit. If `count` is `2`, `ValueSource::reference(StateNamespace::Default, "count")`
reads `2` even when native or structured updates propose `5`. After the native finalizer,
structured updates override native updates to the same field; omitted model values leave
native updates intact.
References copy JSON values directly, including nested objects; no native map deserialization is involved.
Core validates and commits the combined updates.

## Next Step and model work

With no `next` section, the wrapped Step's finalizer keeps control of the destination. Set
`next` to a `NextStep` containing the complete list of `NextCase` candidates.
When configured, `next` overrides the destination returned by the wrapped Step's finalizer.
Each case specifies its destination and selection description; a destination of
`None` means root completion. One candidate is deterministic, while multiple
candidates require model selection. `NextStep::default()` explicitly selects
completion. Steps in child Flows must still return through declared exits.

The wrapped Step decides whether this turn calls a model. When it returns `Template`,
structured rules extend that template. The original goal and `allow_restore` are retained.
Structured model criteria replace native criteria for the same fields, while unconfigured
criteria remain. `next` replaces the model's next-Step choices when supplied.

When the wrapped Step returns `Skip`, the wrapper also skips the model. Constants,
State references and a single next candidate can still apply. An advancing turn with
model-sourced updates or multiple next candidates returns an error if the model was
skipped; no State or transition is committed. Checkpoint restores pass through.

Model criteria use the core Tera context: `state`, `input`, `trace`, `step`, and
`context`. `state` is the current State before commit. Input, Trace and Step-local
context retain their existing Scope semantics.

## Validation

`.with(existing_step)` returns Core's `BuildError` for duplicate fields/routes, empty candidate lists,
invalid references, blank criteria and invalid criterion templates, regardless of how the
spec was constructed. Runtime failures use `FlowError`; template, JSON and type-validation errors
retain their causes through `source()`. Core validates declared model criteria before its request.
Finalization resolves deterministic values and validates destinations. Core validates
concrete State types and commits State, cursor and Trace together.
