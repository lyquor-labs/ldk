# Flow runtime

`lyquid-flow` owns workflow graphs, the `Step` contract, typed input contracts, model-turn execution,
State, Trace, and checkpoint commitment. Steps supply proposals; Scope validates and commits them.

The [`types` module](src/types/README.md) provides structural declarations, direct JSON value
validation, and type inference.
Its public data API is `Type`, `Type::validate` and `Type::infer`. Checked variable storage belongs
to State's private implementation; there is no public `Variable` holder or `Type::Variable` variant.

State stores `serde_json::Value` with a separate immutable `Type` declaration per field.
Initialization and finalized updates are validated against that declaration before mutation.
For example, use `.field("count", "Current count", Type::U64, json!(0))`, then
`state.get("count").and_then(serde_json::Value::as_u64)`; native structs use explicit Serde conversions.

`InputSpec` can be built in Rust or deserialized from its JSON `{ ui, schema }` representation.
JSON loading checks the UI structure and supported schema. Submissions are schema-validated
and bound atomically as JSON values. Native field types supply Schemars declarations.

For declarative State updates and next-Step selection around an existing Step, use the optional
[lyquid-structured-builder](../lyquid-structured-builder/README.md) crate. Input forms, model goals,
finalization and summaries remain in the original Step. The runtime does not depend on the builder.

External Step implementations use read-only `State::get` and `Scope::get` to access JSON values
through JSON accessors or Serde conversion. `Scope::validate_next` preflights a
destination before model or operation effects. Scope owns final turn validation and commitment.
The model phase handles request execution, proposal parsing, and usage reporting.
Its response contract describes State fields using their serialized `Type` declarations
(`kind`/`value`), and proposed values are checked directly against those declarations.

`ModelTemplate::allow_restore` controls whether the model response contract offers checkpoint restoration
and whether the parser accepts it. Native templates allow restores by default. Structured wrappers preserve
the original template's setting; Restore results from the native finalizer bypass structured advance rules.
Application-driven `Scope::restore` is independent.

`State::to_json()` projects committed field values as a JSON object for read-only templates and inspection.
Projection is infallible and excludes field descriptions and in-flight updates. Model prompts use this
projection; Step finalizers supply Trace summaries.

`Step::model_context` supplies optional Step-local data to model templates as `context`; existing
Steps receive an empty object by default. Scope resolves it after interactive input validation and
before sending a model request. The goal and every criterion render once with that data alongside
`state`, `input`, `trace`, and `step`. The hook must be pure, and errors reject the turn before the model
or finalization runs. Structured wrappers delegate this hook to the original Step.

## Mounting child Flows

`Flow` implements `Step` and can be mounted with `FlowBuilder::flow`.
To supply another Step for the mount, construct it from a clone of the child Flow.
`FlowBuilder::flow_with` configures the mount's exit transitions and Trace mode, then registers
the Flow and Step under the same local ID:

```rust
use lyquid_flow::{ExitTransitions, Flow, TraceMode};

let parent = Flow::builder("parent")
    .entry("child")
    .exit("done")
    .flow_with(
        "child",
        child,
        ExitTransitions::new().transition("done", "done")?,
        TraceMode::Expanded,
        step,
    )
    .build()?;
```

The supplied Step's `input` and `model_template` run before the child starts, and its `finalize`
runs after the child completes. Its `view` presents results unless the parent defines a Flow-level view.
The Step's accepted input stays in the parent Scope for finalization and retries, and is cleared on commit.

The child must declare the mapped `done` exit. The Step must preserve the Flow's entry proposal
and delegate finalization to the Flow.

## Error boundaries

Flow, structured Step, and initial State assembly return `BuildError(Diagnostics)`. Shared input/UI
builders and validation helpers return phase-neutral diagnostics instead. `Diagnostics` contains
`diagnostics: Vec<Diagnostic>`: one entry for an ordinary failure, or all collected validation errors.
Each diagnostic carries context, a message, and an optional original source. A single diagnostic's
cause is also available through `Error::source`; for a batch, inspect each diagnostic's source.

Runtime operations return `FlowError`. Its `Execution(Diagnostics)` variant covers dynamic input/view
generation, internal validation, application callbacks, and transitions. `Model` retains provider
errors. `InputInvalid`, `NoPendingInput`, and `InputClosed` retain input submission semantics.
The caller of a shared validator chooses whether its diagnostics represent assembly or execution failure.

A Flow registered through `.step(id, flow)` fails during execution without committing the turn;
use `.flow(...)` to mount its child graph.

`check_json_schema` returns a `Diagnostic`; `validate_json_schema` returns an `InputError` with a
value path and message. During execution, internal schema failures become execution diagnostics.
Rejected user submissions remain `FlowError::InputInvalid` with their existing JSON representation.

Callbacks, model parsing, views, and service schedulers return `FlowError`.
Service initializers assemble a Scope and return `BuildError`. Use
`FlowError::context("operation", error)` to retain a runtime cause, or `"message".into()` for an
application diagnostic. Context is rendered once. Convert errors to text only for presentation
or protocol responses.

```rust
use lyquid_flow::Flow;

let error = Flow::builder("example").build().err().unwrap();
assert_eq!(error.0.diagnostics[0].context, "Flow entry");
```

State fields use explicit structural declarations and JSON payloads. Application consumers enforce
native Rust constraints through Serde conversions and their own validation. A failed turn preserves
committed State, cursor and Trace. A later view publication failure leaves completed commits and
external action effects in place.
