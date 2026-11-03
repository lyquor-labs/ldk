# Structured Builder

`lyquid-structured-builder` adds State updates and next-Step selection to core
[`Step`](../lyquid-flow/README.md) objects.

`StructuredSpec` contains `inputs`, `output`, `state_updates`, and `next`, defined together in
[`src/spec.rs`](src/spec.rs). Its `typed-builder`-derived
builder sets each whole field once, in any order; `.build()` returns the spec. Use `.with(existing_step)`
to validate it and wrap an existing Step. The existing
Step's model contract incorporates the structured rules. Its finalizer runs before
structured updates revise the uncommitted result.
Descriptions, input forms, model goals and summaries remain in the original Step.
In this example, `existing_step` supplies a model template for the structured model rules.

```rust
use lyquid_flow::{BuildError, StateNamespace, Step};
use lyquid_structured_builder::{NextStep, StructuredSpec, StructuredStep, ValueSpec};

fn assess(existing_step: impl Step + 'static) -> Result<StructuredStep, BuildError> {
    StructuredSpec::builder()
        .state_updates(vec![
            ("status".into(), ValueSpec::constant("assessed")),
            ("previous_count".into(), ValueSpec::reference(StateNamespace::Default, "count")),
            ("count".into(), ValueSpec::model("Derive the count from {{ state.request }}")),
        ])
        .next(vec![
            NextStep { next: Some("approve".into()), description: "The request meets the requirements".into(), inputs: vec![] },
            NextStep { next: Some("reject".into()), description: "The request does not meet the requirements".into(), inputs: vec![] },
        ])
        .build()
        .with(existing_step)
}
```

Register an ordinary wrapped Step with `Flow::builder("name").step(id, step)`.
`Flow` implements `Step`, so it can be passed directly to `spec.with(...)`.
Register its child graph explicitly with Core's `.flow_with(...)`:

```rust
use lyquid_flow::{ExitTransitions, Flow, TraceMode};
use lyquid_structured_builder::{StructuredSpec, ValueSpec};

let spec = StructuredSpec::builder()
    .state_updates(vec![("reviewed".into(), ValueSpec::constant(true))])
    .build();
let parent = Flow::builder("parent")
    .entry("child")
    .exit("done")
    .flow_with(
        "child",
        child.clone(),
        ExitTransitions::new().transition("done", "done")?,
        TraceMode::Expanded,
        spec.with(child)?,
    )
    .build()?;
```

Here `child` declares the `done` exit, and the parent State declares a Boolean `reviewed` field.
After the child completes, its Flow finalizer maps the exit and supplies accumulated State updates
and Trace. Structured rules then revise that proposal before the parent Scope validates and commits it.
References read the parent's State before the child's updates are committed.

The spec also supports direct struct construction and serde JSON serialization:

```rust
let spec = StructuredSpec {
    state_updates: vec![("reviewed".into(), ValueSpec::constant(true))],
    ..Default::default()
};
let json = serde_json::to_string(&spec)?;
let restored: StructuredSpec = serde_json::from_str(&json)?;
let step = restored.with(existing_step)?;
```

JSON stores only the structured rules; the existing Step is supplied by Rust code.

## Inputs and output

`inputs: Vec<Input>` declares each parameter's name, description, required flag, and Core
[`Type`](../lyquid-flow/src/types/README.md). Requiredness controls presence; `Type::Option(...)`
permits null. These parameters are separate from Core's interactive `Step::input()` forms.
`output: Option<Output>` declares one result's description, type, and `ValueSpec` recipe;
omitting it means no result.

`validate_inputs()` and `validate_output()` check supplied values against these declarations.
Inputs must be an object containing only declared keys; absent inputs are treated as empty.
`.with(...)` validates definitions, but runtime enforcement, recipe evaluation, and argument
transport for these declarations are not implemented yet.

## Value specifications

Set `state_updates` to a list of `(field, source)` pairs.
`field` names a variable declared in the current Scope's State. `source` is one of
three `ValueSpec` variants:

- `Constant { value }`: a fixed JSON value checked against the destination State's Type declaration.
  `ValueSpec::constant(value)` constructs this variant.
- `State { namespace, field }`: reads the value of a field in that namespace.
  `ValueSpec::reference(namespace, field)` constructs this variant.
- `Model { description }`: instructions describing when to change the field and what
  its replacement should contain. `ValueSpec::model(description)` constructs this variant.

Structured references and model criteria read this turn's current State
before commit. If `count` is `2`, `ValueSpec::reference(StateNamespace::Default, "count")`
reads `2` even when native or structured updates propose `5`. After the native finalizer,
structured updates override native updates to the same field; omitted model values leave
native updates intact.
References copy JSON values directly, including nested objects; no native map deserialization is involved.
Core validates and commits the combined updates.

## Next Step and model work

An empty `next` list preserves the wrapped Step's model choices and final routing.
Set `next` to a nonempty `Vec<NextStep>` to replace them with the complete list of candidate destinations.
Each candidate specifies its destination and selection description; a destination of
`None` means root completion. One candidate is deterministic, while multiple
candidates require model selection. Steps in child Flows must still return through declared exits.

`NextStep.inputs` binds destination parameter names to `ValueSpec` recipes. Root completion
(`next: None`) cannot receive arguments. Definitions are validated by `.with(...)`;
argument evaluation and transport are not implemented yet.

The wrapped Step decides whether this turn calls a model. When it returns `Template`,
structured rules extend that template. The original goal and `allow_restore` are retained.
Structured model criteria replace native criteria for the same fields, while unconfigured
criteria remain. `next` replaces the model's next-Step choices when nonempty.

When the wrapped Step returns `Skip`, the wrapper also skips the model. Constants,
State references and a single next candidate can still apply. An advancing turn with
model-sourced updates or multiple next candidates returns an error if the model was
skipped; no State or transition is committed. Checkpoint restores pass through.

Model criteria use the core Tera context: `state`, `input`, `trace`, `step`, and
`context`. `state` is the current State before commit. Input, Trace and Step-local
context retain their existing Scope semantics.

## Validation

`.with(existing_step)` returns Core's `BuildError` for duplicate fields/routes,
invalid references, blank criteria and invalid criterion templates, regardless of how the
spec was constructed. Runtime failures use `FlowError`; template, JSON and type-validation errors
retain their causes through `source()`. Core validates declared model criteria before its request.
Finalization resolves deterministic values and validates destinations. Core validates
concrete State types and commits State, cursor and Trace together.
