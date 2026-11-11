# Structured Builder

`lyquid-structured-builder` adds I/O handoff, State updates and next-Step selection to core
[`Step`](../lyquid-flow/README.md) objects.

`StructuredSpec` contains `inputs`, `output`, `state_updates`, and `next_steps`, defined together in
[`src/spec.rs`](src/spec.rs). Its `typed-builder`-derived
builder sets each whole field once, in any order; `.build()` returns the spec. Use `.with(existing_step)`
to validate it and wrap an existing Step. The existing
Step's model contract incorporates the structured rules. Its finalizer runs before
structured updates revise the uncommitted result.
Descriptions, input forms, model goals and summaries remain in the original Step.
The containing Flow owns the state view; wrappers do not add or delegate a Step view.
In this example, `existing_step` supplies a model template for the structured model rules.

```rust
use lyquid_flow::{BuildError, StateNamespace, Step};
use lyquid_structured_builder::{NextStep, StructuredSpec, StructuredStep, ValueSpec};

fn assess(existing_step: impl Step + 'static) -> Result<StructuredStep, BuildError> {
    StructuredSpec::builder()
        .state_updates(vec![
            ("status".into(), ValueSpec::constant("assessed")),
            ("copied_count".into(), ValueSpec::reference(StateNamespace::Default, "count")),
            ("count".into(), ValueSpec::model("Derive the count from {{ state.request }}")),
        ])
        .next_steps(vec![
            NextStep { step_id: Some("approve".into()), description: "The request meets the requirements".into(), inputs: vec![] },
            NextStep { step_id: Some("reject".into()), description: "The request does not meet the requirements".into(), inputs: vec![] },
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
Post-Step State references read those proposed updates, falling back to the parent's committed State.

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

Step implementations validate values when consuming them; `validate_inputs()` is an optional whole-object check.
Input declarations are not automatically enforced. `.with(...)` validates definitions; Output is checked when resolved.
A consumer's validation error rejects its turn; earlier committed turns remain intact.

`state_builder` initializes `__input` with entry arguments and `__output` with null, both as `Type::Dynamic`:

```rust
use lyquid_structured_builder::state_builder;

let state = state_builder([("request".into(), serde_json::json!("review"))]).build()?;
```

Use `[]` for no arguments and `.field(...)` to add ordinary State fields.

After native Finalization, the wrapper resolves Output, then uses the current Step's inputs and evaluated output
for State Updates and Next Step arguments. Native results come from `updates.set("__output".into(), Some(value))`;
missing native results and omitted Output use JSON null for now. Commit replaces `__input` with the destination's
arguments (`{}` when none) and `__output` with the evaluated output. These fields cannot be targets in `state_updates`.

## Value specifications

Set `state_updates` to a list of `(field, source)` pairs.
`field` names a variable declared in the current Scope's State. `source` is one of
three `ValueSpec` variants:

- `Constant { value }`: a fixed JSON value checked against the destination State's Type declaration.
  `ValueSpec::constant(value)` constructs this variant.
- `State { namespace, field }`: reads the value of a field in that namespace.
  `ValueSpec::reference(namespace, field)` constructs this variant. The namespace is `Default`
  for ordinary State or `Input` for submitted interactive input (`"default"` / `"input"` in JSON).
- `Model { description }`: instructions describing when to change the field and what
  its replacement should contain. `ValueSpec::model(description)` constructs this variant.

During Finalization, the wrapper first delegates to the native Step's `finalize()`,
then applies `StructuredSpec.state_updates` as post-Step State updates. State references
read native proposed updates, falling back to committed State; Input references read submitted input.
For example, if committed `count` is `2` and the native finalizer proposes `count = 5`,
`ValueSpec::reference(StateNamespace::Default, "count")` reads `5` before commit.
Constant and State-reference updates resolve before any of them are applied, so their
list order does not affect the result.

For ordinary State fields, structured updates override native updates to the same field;
other native updates remain intact.
Model-derived values use information available during the earlier Model Prompt phase;
omitted model values leave native updates intact.

References copy JSON values directly, including nested objects; no native map deserialization is involved.
Core validates and commits the combined updates.

## Next Step and model work

An empty `next_steps` list preserves the wrapped Step's model choices and final routing.
Set `next_steps` to a nonempty `Vec<NextStep>` to replace them with the complete list of candidate destinations.
Each candidate specifies its destination as `step_id` and a selection description; a destination of
`None` means root completion. One candidate is deterministic, while multiple
candidates require model selection. Steps in child Flows must still return through declared exits.

`NextStep.inputs` binds argument names to `ValueSpec` recipes, resolved during Finalization against proposed State,
falling back to committed State. Root completion (`step_id: None`) cannot receive arguments;
an empty `next_steps` list preserves native routing with an empty argument object.
Model-derived I/O remains a TODO pending model response-schema support and returns an unsupported error.
State references still name whole fields; field-path references remain a TODO.

The wrapped Step decides whether this turn calls a model. When it returns `Template`,
structured rules extend that template. The original goal and `allow_restore` are retained.
Structured model criteria replace native criteria for the same fields, while unconfigured
criteria remain. `next_steps` replaces the model's next-Step choices when nonempty.

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
