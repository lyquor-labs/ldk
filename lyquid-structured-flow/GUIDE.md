# Structured Flow usage guide

This guide shows how to compose structured Steps into a native Flow and export its configuration.
See the [module overview](README.md) for its relationship to `lyquid-flow`, and the
[structured-Step guide](../lyquid-structured-step/GUIDE.md) for Step behavior and bindings.

- [Quick start](#quick-start)
- [Build a graph](#build-a-graph)
- [Configure Step routes](#configure-step-routes)
- [Run and inspect a Flow](#run-and-inspect-a-flow)
- [Export configuration](#export-configuration)
- [Handle validation and failures](#handle-validation-and-failures)

## Quick start

This Flow increments a caller-supplied counter and exits through `done`. The named action retains
its reference and settings for JSON export; Scope runs the Rust callback.

```rust
use lyquid_structured_flow::{StructuredFlowBuilder, StructuredStepBuilder};
use lyquid_flow::{AutoCheckpointConfig, Scope, State};

let builder = StructuredFlowBuilder::new("counter")
    .description("Increment a counter")
    .entry("increment")
    .exit("done")
    .step("increment", StructuredStepBuilder::new()
        .data::<u64>("count")
        .result::<u64>()
        .bind_state("count", "count")
        .action_with_config("counter.increment", (), |context, _, &()| {
            Ok(context["count"].as_u64().ok_or("invalid count")? + 1)
        })
        .update("count", "")
        .next("done"));

let json = builder.to_json()?;
let flow = builder.build()?;
let state = State::builder().field("count", "Current count", 7_u64).build()?;
let mut scope = Scope::new(flow.into(), state, AutoCheckpointConfig::Disabled, None);
scope.advance()?;
assert_eq!(scope.state().get::<u64>("count"), Some(&8));
assert!(scope.is_finished());
```

## Build a graph

Import `StructuredFlowBuilder` from `lyquid_structured_flow`. `StructuredStepBuilder` and
`ValueSource` are re-exported for convenience.
Builder methods consume and return the builder unless their return value is shown below.

| Rust API | Purpose | Example |
| --- | --- | --- |
| `StructuredFlowBuilder::new(id)` | Starts an empty graph with a nonblank identifier. | `StructuredFlowBuilder::new("checkout")` |
| `.description(text)` | Sets the Flow description. | `.description("Review an order")` |
| `.entry(id)` | Declares the single Step where execution starts. | `.entry("review")` |
| `.exit(id)` | Declares a named exit that Step routes may select. | `.exit("approved")` |
| `.step(id, builder)` | Adds a typed `StructuredStepBuilder<C, O, I>` and retains its configuration and Rust behavior. | `.step("review", StructuredStepBuilder::new().next("approved"))` |
| `.clone()` | Copies a builder for another variant; executable callbacks are shared. | `let variant = builder.clone().description("Another review");` |
| `.build()` | Validates the graph, builds its Steps, and returns `Result<lyquid_flow::Flow, String>`. | `let flow = builder.build()?;` |

A graph requires exactly one entry, and that entry must name a registered Step. Node and exit
names must be nonblank and unique; an exit cannot also name a node. Configure each Step before
passing it to `.step(...)`, as in the quick start.

## Configure Step routes

Routes belong to each `StructuredStepBuilder`. The Flow validates their destinations without maintaining a
second edge table. A destination can name a local Step, a declared exit, or root completion.

| Step API | Purpose | Example |
| --- | --- | --- |
| `.next(id)` | Selects one fixed Step or exit. | `.next("approved")` |
| `.complete()` | Selects root completion. This is also the default route. | `StructuredStepBuilder::new().complete()` |
| `.route_by(pointer, cases)` | Selects a destination by matching a string in the final action result. | `.route_by("/decision", [("yes", "approved"), ("no", "review")])` |
| `.proposed_next()` | Keeps the destination selected by the model; configure permitted destinations with `.with_model(...)`. | `StructuredStepBuilder::new().with_model(template).proposed_next()` |

See the Step guide for [bindings, routing, and summaries](../lyquid-structured-step/GUIDE.md#bindings-routing-and-summary)
and [model configuration](../lyquid-structured-step/GUIDE.md#input-model-and-actions).

## Run and inspect a Flow

`.build()` returns the native `lyquid_flow::Flow`. Wrap it in `Arc` to share the graph between
Scopes, each with its own State and runtime services:

```rust
let flow = std::sync::Arc::new(builder.build()?);
let mut scope = Scope::new(flow.clone(), state, AutoCheckpointConfig::Disabled, None);
```

Inspect execution through Scope's `current_step()`, `state()`, and `trace()` methods. The structured
builder remains in its separate crate; construction adds no wrapper around the native Flow.

This graph-building layer adds no Flow-level State declarations, invocation inputs, data outputs,
or configured child-mount API. Scope owns execution, input handling, model services, tracing,
checkpoints, and retries. Native builders and custom Steps remain available for advanced composition.

## Export configuration

The same Rust builder supports native compilation and configuration export. Exportable Step APIs
such as `.action_with_config(...)` and `.operation_with_config(...)` retain callback references and
settings. Opaque callbacks such as `.action(...)` can build natively, but cause export to return an
error. See [Export Step configuration](../lyquid-structured-step/GUIDE.md#export-step-configuration).

Export before `.build()` consumes the builder, or retain a builder clone for later export. The
built native Flow does not carry export metadata or a Flow-level export error.

| Rust API | Purpose | Example |
| --- | --- | --- |
| `builder.to_json()` | Validates and pretty-prints the authored definition. | `let json = builder.to_json()?;` |

The Rust export representation is internal. Consumers can inspect the exported JSON without
depending on `FlowDefinition`, `Node`, or `Component` as public Rust types. The Configurable Flow
work in [#1673](https://github.com/lyquor-labs/lyquor/issues/1673) will establish the shared typed
configuration API needed for declarative loading and graphical authoring.

### Exported JSON fields

| Field | Purpose | Example |
| --- | --- | --- |
| `version` | Identifies the exported format; builders currently emit version `1`. | `1` |
| `id`, `description`, `entry`, `exits` | Describe the graph and its entry and exits. | `"entry": "review"` |
| `nodes` | Stores ordered components, each with an `id` and `component`. | `"id": "review"` |
| `component.kind`, `component.configuration` | Identifies a Step and stores its `StepConfiguration`, including wiring, schemas, and exportable phase configuration. | `"kind": "step"` |

For example, the exported node contains a tagged Step component:

```rust
use lyquid_structured_flow::{StructuredFlowBuilder, StructuredStepBuilder};

let builder = StructuredFlowBuilder::new("review")
    .entry("review")
    .exit("approved")
    .step("review", StructuredStepBuilder::new().next("approved"));
let json = builder.to_json()?;
let exported: serde_json::Value = serde_json::from_str(&json)?;
assert_eq!(exported["version"], 1);
assert_eq!(exported["nodes"][0]["component"]["kind"], "step");

assert_eq!(exported["entry"], "review");
let flow = builder.build()?;
```

Parsing the exported JSON reads configuration data. Rust builders still compile executable
workflows. The [design's Configurable Flow layer](https://docs.superhuman.com/d/Lyquid-Flow_dEIF_s98LeI/Implementation-Items_suwN_toU)
requires declarative construction, with every contained Step and nested Flow configurable recursively.
That capability, the proposed `ConfigurableStep` contract, and host capability resolution belong to
[#1673](https://github.com/lyquor-labs/lyquor/issues/1673); exporting JSON alone does not implement them.
Flow and Step ViewSpec work belongs to
[#1667](https://github.com/lyquor-labs/lyquor/issues/1667).

## Handle validation and failures

| Operation | Checks and failure behavior |
| --- | --- |
| `to_json()` on a builder | Rejects invalid graph declarations, unknown fixed/result/model destinations, and non-exportable Step configuration. Does not execute callbacks or models. |
| `build()` | Validates the graph and builds each structured Step. Model-route checks still apply when callbacks are intentionally non-exportable. Correct invalid declarations and rebuild. |
| Scope execution | Uses the existing native Step lifecycle and atomic State commit. A failed Step can repeat external effects on an explicit retry; the structured builder adds no executor or retry policy. |

Every attached model must declare at least one next-step criterion. Model destinations (including
root completion) and State-update field names must each be unique. Build/export checks these
declarations even for native-only callbacks and Steps with fixed routing. State-field existence
still depends on the caller-provided State and is checked by Scope.
