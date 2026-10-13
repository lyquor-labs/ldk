# Configured-step usage guide

This guide shows how to configure and run Steps with `lyquid-configured-step`, using Rust builders
or JSON wiring with typed behavior supplied by the application. See the [module overview](README.md)
for its purpose and relationship to the Flow runtime.

- [Choose phase components](#choose-phase-components)
- [Quick start](#quick-start)
- [Rust and JSON API reference](#api-reference)
- [Configure bindings, routing, and trace summaries](#configure-a-step)
- [Save and load JSON wiring](#save-and-load-json-wiring)
- [Declare data contracts](#declare-data-contracts)
- [Export Step configuration](#export-step-configuration)
- [Collect input](#collect-input)
- [Define actions and prepare context](#define-actions)
- [Handle execution and failures](#handle-execution-and-failures)

## Choose phase components

`StepBuilder::build()` returns an implementation of the existing `lyquid-flow::Step` hooks. Choose the work in each phase:

| Phase | Reusable components | How to skip optional work |
| --- | --- | --- |
| Input | Flow's `InputSpec` field builders: text, numeric, choice, and other supported controls with typed validation. | Omit `with_input` and input factories. |
| Model | Flow's `ModelTemplate`: goal, permitted destinations, and State update criteria. | Omit `with_model`. |
| Finalize | Repeated `.action(unit)` calls, including formatters, decoders, and other host-supplied operations; whole-step bindings, routing, and summary. | Omit `.action(...)` when no custom processing is needed. |

There is still a finalization hook and an atomic runtime commit for every successful step. Skipping
custom processing does not skip bindings, routing, trace rendering, or validation. Input-only,
model-only, processing-only, and combined steps all use the same runner.

Use one `StepBuilder` chain for both wiring and behavior. Start with `new()`, attach
an optional `InputSpec` and `ModelTemplate`, append finalization functions with `.action(...)`, configure wiring, and call
`build()` to get a Step for `Flow::builder().step(...)`. Typed Rust operation and proposed-value
constructors are also available. Reusable application behavior is an ordinary Rust function passed
to `action`; formatters use the same callback contract. Flow runs the resulting Step through its
existing lifecycle.

## Quick start

This example binds a committed State field to a typed context, increments it with an operation, and
writes the result back to State. The Flow declares the destination and State field, then Scope runs
and commits the step.

```rust
use std::sync::Arc;

use lyquid_configured_step::StepBuilder;
use lyquid_flow::{AutoCheckpointConfig, Flow, Scope, State};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Context {
    count: u64,
}

let step = StepBuilder::operation(|context: &Context| {
    Ok(Context { count: context.count + 1 })
})
    .description("Increment a counter")
    .bind_state("count", "counter")
    .update("counter", "/count")
    .next("done")
    .summary("Incremented {{ context.count }} to {{ result.count }}")
    .build()
    .unwrap();

let flow = Flow::builder("counter-flow")
    .entry("increment")
    .step("increment", step)
    .exit("done")
    .build()
    .unwrap();
let state = State::builder()
    .field("counter", "Current count", 7_u64)
    .build()
    .unwrap();
let mut scope = Scope::new(Arc::new(flow), state, AutoCheckpointConfig::Unbounded, None);

scope.advance().unwrap();
assert_eq!(scope.state().get::<u64>("counter"), Some(&8));
assert!(scope.is_finished());
```

To store wiring or import it from a UI, see [Save and load JSON wiring](#save-and-load-json-wiring).

## API reference

Import `StepBuilder` and the configuration data types from `lyquid_configured_step`. All fluent
methods below belong to `StepBuilder`; the serialized structs contain data only.

The types table shows serialized values. Wiring methods show the corresponding fields inside a complete
`StepWiring`, which requires `description`, `bindings`, `next`, and `summary`. Field names and values
in the JSON examples are illustrative. **Rust/host only** means the crate provides no JSON configuration
for that API; the application supplies its behavior in Rust or through the host.

### Step-building APIs

These methods describe what the Step does. Start with `StepBuilder::new()`, optionally attach an input
specification and a model template, then append `.action(unit)` calls in execution order. Omitted components
are skipped automatically. There are no explicit bypass or disable methods. Bindings, routing, and
summary rendering still finalize every successful turn.

#### Input, model, and actions

| Rust API | JSON format | Purpose |
| --- | --- | --- |
| `with_input(input_spec: InputSpec)` | `input: {kind: "static", specification: {ui, schema}}`; the specification is `InputSpec` data. | Attaches a spec built in Rust or loaded from JSON. JSON fields use schema-validated JSON values, which bindings decode into typed arguments or State. |
| `with_input_factory(factory)` | Rust/host only. | Builds input presentation from the current read-only Scope. |
| `with_fallible_input_factory(factory)` | Rust/host only. | Builds input presentation that can fail; errors reject the turn before model or action execution. |
| `with_model(template)` | `model: {goal, next, state_updates, allow_restore}` from the native `ModelTemplate`. | Configures goal, permitted destinations and State-update criteria. Fixed/result routing disables model restores. Scope supplies the model backend. |
| `action(unit)` | An opaque Rust callback; use `action_with_config` for exportable references/settings. | Appends a supplied action in order. Rust calls the supplied implementation directly. See the contract below. |

`action_named(name, unit)` also retains that action's output for later actions and final bindings.
Names must be nonblank and unique within the chain; only named outputs require serialization.

The JSON input object can be deserialized as `InputSpec` data. Complete Step configuration is exported
through `.to_json()` on the same `StepBuilder` or its built Step; it does not create a JSON runtime.
A formatter is an ordinary `.action(formatter)` callback. For export, give the formatter an explicit
reference and settings with `.action_with_config(...)`.

#### Bindings, routing, and summary

| Rust API | JSON format | Purpose |
| --- | --- | --- |
| `description(text)` | `{"description":"Count"}` | Sets the description independently of the summary. |
| `bind(from, to)` | `{"bindings":[{"from":{"kind":"state","field":"counter"},"to":{"kind":"context","name":"count"}}]}` | Adds any supported source-to-target mapping. |
| `bind_state(name, field)` | `{"bindings":[{"from":{"kind":"state","field":"counter"},"to":{"kind":"context","name":"count"}}]}` | Supplies a context argument from committed State. |
| `bind_input(name, input)` | `{"bindings":[{"from":{"kind":"input","name":"answer"},"to":{"kind":"context","name":"message"}}]}` | Supplies a context argument from validated input. |
| `bind_execution_id(name)` | `{"bindings":[{"from":{"kind":"execution_id"},"to":{"kind":"context","name":"execution_id"}}]}` | Supplies a context argument containing the current execution ID. |
| `update(field, pointer)` | `{"bindings":[{"from":{"kind":"result","pointer":"/count"},"to":{"kind":"state","field":"counter"}}]}` | Replaces a State field with a value selected from the action result. |
| `update_from(field, source)` | `{"bindings":[{"from":{"kind":"state","field":"counter"},"to":{"kind":"state","field":"previous_count"}}]}` | Replaces a State field from any supported source; this example copies committed State. |
| `constant(field, value)` | `{"bindings":[{"from":{"kind":"constant","value":7},"to":{"kind":"state","field":"counter"}}]}` | Replaces a State field with a constant JSON value. |
| `next(step)` | `{"next":{"kind":"fixed","next":"done"}}` | Selects a fixed Step or declared exit. |
| `complete()` | `{"next":{"kind":"fixed","next":null}}` | Completes a root Flow; mounted Flows must select an exit. |
| `route_by(pointer, cases)` | `{"next":{"kind":"result","pointer":"/route","cases":[{"value":"yes","next":"done"}]}}` | Selects a declared destination by matching a string in the action result. |
| `proposed_next()` | `{"next":{"kind":"proposed"}}` | Retains the model-selected destination instead of overriding it with fixed/result routing. |
| `summary(template)` | `{"summary":"Count {{ result.count }}"}` | Sets the Tera trace template, with access to committed `state`, prepared `context`, the final `result`, `model_response`, and named `actions` outputs. |

Each binding helper appends to `bindings`. State replacements take effect only when the entire turn
succeeds. Use the Rust import/export utilities below to work with saved wiring.

### Rust integration and utility APIs

These APIs construct, reuse, inspect, or convert Rust objects; they are separate from the Step's
input/model/action configuration. `clone()` and `build()` are coding operations with no JSON fields.
For `StepBuilder<C, O, I>`, `I` is the decoded binding input, `C` the prepared context, and `O` the
finalization result. Callbacks usually infer these types.

| Rust API | JSON format | Purpose |
| --- | --- | --- |
| `StepBuilder::new()` / `default()` | Default wiring: `{"description":"Step","bindings":[],"next":{"kind":"fixed","next":null},"summary":"Step"}`. | Starts with no input, model, or custom actions. Until an action is attached, the prepared JSON context is the result. |
| `StepBuilder::operation(operation)` | Rust/host only. | Runs an operation in finalize, returning a typed result or an error without a model call. |
| `StepBuilder::<C, O>::proposed(field)` | `finalization.input: {kind: "proposed", field}`. | Selects an `O: Value + Clone` from proposed State updates for processing. The model must declare the field; a missing proposed value fails finalization. |
| `with_context(prepare)` | Rust/host only. | Decodes bindings as `I`, then prepares `C`; `C` need not implement Deserialize. Preparation must be pure. |
| `wiring()` | Returns a borrowed `StepWiring`. | Exports the current wiring for serialization or inspection, including drafts not yet validated by `build`. |
| `with_wiring(wiring)` | Accepts a complete `StepWiring` object. | Replaces wiring while retaining behavior, context preparation, input, and model. |
| `clone()` | No serialized operation. | Reuses a configured builder for independent variants; executable callbacks are shared. The built Step is also cloneable. |
| `build()` | Validates imported JSON using the same rules as Rust wiring. | Checks static configuration and returns `Result<ConfiguredStep<C, O>, String>`. Does not execute callbacks. Scope-dependent checks run before model/action effects. |

### Serialized configuration types

| Rust API | JSON format | Purpose |
| --- | --- | --- |
| `StepWiring { description, bindings, next, summary }` | `{"description":"Count","bindings":[],"next":{"kind":"fixed","next":"done"},"summary":"Count"}` | Serializable wiring, routing, and trace configuration for one step. |
| `Binding { from, to }` | `{"from":{"kind":"state","field":"counter"},"to":{"kind":"context","name":"count"}}` | Maps one source to one target. |
| `ValueSource::State { field }` | `{"kind":"state","field":"counter"}` | Reads a whole field from committed State. |
| `ValueSource::Input { name }` | `{"kind":"input","name":"answer"}` | Reads a validated input field. |
| `ValueSource::InputOr { name, default }` | `{"kind":"input_or","name":"answer","default":""}` | Uses the fallback only when an optional input field is absent. |
| `source.at(pointer)` | `{"kind":"select","source":{"kind":"state","field":"request"},"pointer":"/items/0"}` | Projects a structured value using JSON Pointer syntax. |
| `ValueSource::ExecutionId` | `{"kind":"execution_id"}` | Reads the current execution ID as a string. |
| `ValueSource::Constant { value }` | `{"kind":"constant","value":7}` | Supplies a literal JSON value. |
| `ValueSource::Context { name }` | `{"kind":"context","name":"count"}` | Reads a field from the prepared action context. |
| `ValueSource::Result { pointer }` | `{"kind":"result","pointer":"/count"}` | Selects the final action result by JSON Pointer. |
| `ValueSource::ModelResponse { pointer }` | `{"kind":"model_response","pointer":"/usage/total_tokens"}` | Selects original model-response data during finalization; requires a model template. |
| `ValueSource::ActionResult { action, pointer }` | `{"kind":"action_result","action":"formatted","pointer":"/answer"}` | Selects a named action's saved output. |
| `BindingTarget::Context { name }` | `{"kind":"context","name":"count"}` | Supplies a temporary argument before context preparation. |
| `BindingTarget::State { field }` | `{"kind":"state","field":"counter"}` | Stages a whole-field State replacement for successful turn completion. |
| `NextStep::Fixed { next }` | `{"kind":"fixed","next":"done"}` | Selects a fixed Step/exit; `"next":null` completes a root Flow. |
| `NextStep::Result { pointer, cases }` | `{"kind":"result","pointer":"/route","cases":[{"value":"yes","next":"done"}]}` | Matches a result string to a declared routing case. |
| `NextStep::Proposed` | `{"kind":"proposed"}` | Keeps the model proposal’s destination, already checked against its declared criteria. Requires a model template. |
| `NextCase { value, next }` | `{"value":"yes","next":"done"}` | Maps one result string to a destination; `"next":null` completes a root Flow. |

## Configure a step

Configure arguments and State replacements with the builder's binding methods, choose a destination
with its routing methods, and set the trace with `summary`. For example, an input-to-State binding
saves an answer while `with_input` selects how to collect it. Bindings must decode to the callback's
expected arguments and the destination State types. Editing a binding does not rewrite the model
template or action processing.

### Bindings

Each binding has a `from: ValueSource` and a `to: BindingTarget`. The target determines when the
mapping takes effect; there are no separate context-binding and State-update lists.

All sources and their permitted targets are:

| Source (`from`) | Selected value | To `Context { name }` | To `State { field }` |
| --- | --- | --- | --- |
| `State { field }` | A whole field from committed State before this turn's writes. | Yes | Yes |
| `Input { name }` | A field from this step's validated input submission. | Yes | Yes |
| `InputOr { name, default }` | A submitted input field, or its explicit absence fallback. | Yes | Yes |
| `ExecutionId` | The current execution ID as a String; mounted steps receive the child's identity. | Yes | Yes |
| `Constant { value }` | A literal JSON value, including objects, arrays, and null. | Yes | Yes |
| `Context { name }` | A named field from the prepared context, after any `with_context` processing. | No | Yes |
| `Result { pointer }` | The last action's result, selected with a JSON Pointer. | No | Yes |
| `ModelResponse { pointer }` | The original response, including text, usage, sources, raw provider JSON, and HTTP data. | No | Yes |
| `ActionResult { action, pointer }` | A named action's saved JSON output, independently of the last result. | No | Yes |

`Select { source, pointer }` preserves its source's phase and permitted targets while selecting a subfield.

There are exactly two target namespaces:

- **`Context { name }`** prepares a named argument before the action runs. Context values are temporary
  and local to this execution of the step; each execution creates a fresh context. They persist only
  if a separate binding saves them to State. Context, Result, ModelResponse, and ActionResult sources cannot
  target Context: prepared arguments are validated before model execution. Named action outputs are
  saved separately in the execution's temporary context by `action_named`.
- **`State { field }`** stages a complete replacement for an existing State field. It is committed only
  when the entire turn succeeds. Bindings do not create State fields, patch nested fields, append, or merge.
  The containing Flow or host declares State fields and retains their typed codecs.

Input, model responses, action results, and execution identity are sources only. Routing and trace rendering have their own
configuration; they are not binding targets. State/Input/Context names select whole named fields.
Result, ModelResponse, and ActionResult use JSON Pointers: `""` selects the complete result, `/catalog` a member, and
`/request/message` a nested member. Pointer segments escape `~` as `~0` and `/` as `~1`.

Input can go directly to State without passing through Context or being returned by an action.
This wiring saves an answer and also makes it available as a temporary action argument:

```json
{
  "description": "Collect an answer",
  "bindings": [
    {
      "from": { "kind": "input", "name": "answer" },
      "to": { "kind": "state", "field": "last_answer" }
    },
    {
      "from": { "kind": "input", "name": "answer" },
      "to": { "kind": "context", "name": "message" }
    }
  ],
  "next": { "kind": "fixed", "next": "done" },
  "summary": "Saved an answer"
}
```

Removing the Context-targeted binding still saves the input when paired with an action accepting an
empty context. The State write remains contingent on successful action execution and trace rendering.

The Rust builder exposes `.bind(from, to)` for every permitted mapping. Convenience methods produce
entries in the same list:

| Method | Mapping |
| --- | --- |
| `bind_state(name, field)` | State to Context |
| `bind_input(name, input)` | Input to Context |
| `bind_execution_id(name)` | Execution ID to Context |
| `update(field, pointer)` | Result to State |
| `update_from(field, source)` | Any permitted source to State |
| `constant(field, value)` | Constant to State |

Use `.bind(ValueSource::Constant { value }, BindingTarget::Context { name })` for a literal action
argument. Constants and all other values must satisfy the destination's type contract; null is not deletion.

List order does not create dependencies. All State reads use the committed snapshot, even when
another binding replaces that field. Each target may appear once; the same name in Context and State
is allowed because they are different namespaces. One source may feed multiple targets.

`build()` checks target names, legal source/target combinations, pointer syntax, duplicate targets,
routing cases, and summary syntax without executing callbacks. Runtime preflight checks actual
graph destinations, context argument decoding, and State writes whose sources are already available. After context preparation,
Context-to-State bindings are checked for missing fields and incompatible values before the action runs.
Missing or incompatible Result values are rejected before committing the turn. Unmapped result fields
never modify State.

### Routing

`next` is a `NextStep`:

- `Fixed { next }` selects a configured Step/exit ID, or `None` to finish a root Flow.
  Mounted child Flows must finish through a declared exit.
- `Result { pointer, cases }` selects a declared case using a string in the action result.
- `Proposed` keeps the destination from the model’s validated proposal; it requires `with_model`.

For example, `.route_by("/outcome", [("success", "next"), ("failed", "failed")])` selects a finite
configured destination. Pointer syntax, duplicate cases, and all destinations are checked before the action.
With a declared result schema, build and export also reject impossible paths and terminal types that
cannot be strings. Unknown shapes, nullable values, and actual array lengths still require runtime checks.
Routing uses the same JSON Pointer syntax as Result bindings. Several cases may share a
destination; missing, unknown, or non-string outcomes reject the turn. Actions cannot supply arbitrary
Step IDs through result routing. In a graph editor, authored edges resolve these destinations.

### Trace template

`.summary(template)` sets the trace-summary template. Tera can read:

- `state`: committed State before this turn's writes, including fields not bound to Context.
- `context`: the prepared action context.
- `result`: the final action result after processing.
- `model_response`: the original response object, or null for a turn without model output.
- `actions`: named successful action results, such as `actions.formatted.answer`.

Nested members and Tera filters are supported. Use bracket notation for non-identifier names, such as
`{{ state["display-name"] }}`. Interpolated values are not executed as templates. Template syntax is
validated by `build()`. Rendering still happens after the action so it can read the result;
data-dependent rendering failures reject the entire turn, including its State writes.

## Save and load JSON wiring

`StepWiring` is the data format used to save and load the builder's wiring. It contains four fields:

| Field | Responsibility |
| --- | --- |
| `description` | Describe the step. The containing Flow owns its Step ID. |
| `bindings` | A single list of `Binding { from, to }` mappings. |
| `next` | Fixed, finite result-based, or model-proposed routing. |
| `summary` | The Tera trace-summary template. |

Input specifications, model templates, and executable callbacks are supplied through the builder separately;
this format contains only the wiring portion of a Step. Rust authors can configure all four fields
through builder methods. JSON/UI hosts use `wiring()` and `with_wiring(...)` to export or
import that same data:

```rust
let saved_json = serde_json::to_string(builder.wiring())?;
let wiring = serde_json::from_str::<lyquid_configured_step::StepWiring>(&saved_json)?;
let step = StepBuilder::operation(increment)
    .with_wiring(wiring)
    .build()?;
```

`with_wiring(...)` replaces wiring while retaining the builder's input, model, context preparation,
and callbacks. `build()` validates the imported wiring and produces the same ordinary Flow Step as
Rust authoring. Binding data remains serializable; callbacks and retained input decoders stay in Rust.

## Declare data contracts

A data declaration describes the required input format: fields, types, requiredness, nested objects,
and array elements. Declare it in Rust and export its JSON Schema with `.to_json()`; it is not a text
template or a sample invocation. `InputSpec` continues to describe interactive input separately.

```rust
use lyquid_configured_step::{StepBuilder, ValueSource};
use schemars::JsonSchema;

#[derive(JsonSchema)]
struct Candidate {
    id: String,
    description: String,
}

#[derive(JsonSchema)]
struct Request {
    user_request: String,
    candidates: Vec<Candidate>,
}

let reusable = StepBuilder::new()
    .data::<Request>("request")
    .result::<String>()
    .action_with_config("describe-request", (), |context, _, &()| {
        context.render("{{ context.request.user_request }}: {{ context.request.candidates | length }} candidates")
    });
let schema = &reusable.data_contract().arguments["request"].schema;
let configuration = reusable.to_json()?; // No candidate values or actions are required to export.
let step = reusable
    .bind_data("request", ValueSource::State { field: "shopping_request".into() })
    .update("description", "")
    .next("done")
    .build()?;
```

`.bind_state("request", "shopping_request")` is shorthand for the binding above. The argument name
remains `request` when another caller binds a different source. `.at("/nested/items/0")` selects a
subfield of a `ValueSource` using JSON Pointer syntax and preserves its value type. Result bindings
already take a pointer through `.update(destination, pointer)`. Bindings do not create State fields;
the caller still provisions typed State. No Flow-entry namespace or JSON executor is added here.

| API | Contract |
| --- | --- |
| `data::<T>(name)` | Required named argument; generate a deserialization schema from `T: JsonSchema`. |
| `optional_data::<T>(name)` | An absent argument is omitted from context; explicit null must satisfy the schema. |
| `data_default(name, value)` | Use this serialized default only when the argument is absent; validate it against its type's schema. |
| `data_schema(name, schema, presence)` | Explicit supported JSON Schema plus `Presence::Required`, `Optional`, or `Default { value }`. |
| `result::<T>()` | Generate the final result's serialization schema and validate the result before committing writes. |
| `data_contract()` | Inspect `StepData` on a builder or built Step, even when its Rust callbacks cannot be exported. |

When arguments are declared, every Context binding must name a declared argument. Bindings supplied
from interactive Input are resolved after submission; they can also have a declaration and an
explicit absence default. The schema's `default` annotation does not supply values by itself.
An explicit `Presence::Default { value: null }` survives a configuration round trip as a null default.
Unbound reusable declarations can be inspected/exported, but native build rejects missing required
bindings. Unsupported schemas, invalid defaults, duplicate names/targets, bad pointers and known
constant/schema mismatches fail without running callbacks. Known impossible result paths fail too,
including paths whose final local reference resolves to a `false` schema.
Result-based routing uses the same projection checks and requires a possible string type.
For a static `with_input(spec)`, build and configuration export also check input field names,
known impossible projections, disjoint declared JSON types, and reachable `InputOr` fallback values.
These checks follow local schema references and type alternatives; `integer` and `number` overlap.
They do not run input factories or actions. Dynamic input schemas, State fields/codecs, overlapping
types, conditional shapes, and value-dependent constraints remain runtime checks before model/actions.
For example, a string-only input bound to a `u64` argument fails construction; an input allowing both
strings and integers builds, then rejects a submitted string at runtime. Array element types can be
checked without knowing the actual array length. Complex schema implication and dynamic Tera accesses
are not statically inferred.

Actions receive the same validated data through their existing typed `ActionContext<C>`.
`ActionContext::render(template)` exposes `context`, earlier named `actions`, `model_response`, and
logical `proposals`. It renders once: inserted strings containing Tera delimiters stay literal.
Summary templates retain their existing context/result/action access. `with_context` can still
prepare a different Rust context type; an opaque preparation function remains non-exportable.

`with_data_input_factory_config(name, settings, factory)` passes a JSON object of bound data and
the typed settings to a pure factory returning `Result<InputSpec, FlowError>`. It does not pass
Scope or require caller State names. Interactive-bound arguments are omitted during presentation,
including when presentation is rebuilt during finalization. Its factory can use nested data to
construct a prompt or choices. Preparation can still run more than once under the existing Step
hooks; context is never cached on the shared Step.

**Model prompts receive prepared context.** A configured Step supplies its validated, prepared
data through `Step::model_context`; the native renderer makes it available as `context` in the goal,
next-step criteria, and State-update criteria. For example, a reusable prompt can read
`{{ context.request.user_request }}` and iterate over `context.request.candidates` while callers bind
`request` to different source fields. Declare every argument the prompt needs, including its current
decision or latest message when applicable. These declarations remain inspectable and export with
the original template text through `.to_json()`.

Model context is resolved after interactive input validation, so named arguments bound from `Input`
are available too. `with_context` transformations apply before rendering, just as they do for actions.
Each authored section renders once: data containing `{{ ... }}` remains literal. Context/schema/
serialization errors prevent the model request and finalization. Context is recomputed from the
current Scope, never stored on the shared Step; pure preparation may run more than once per attempt.
The existing native namespaces `state`, `input`, `trace`, and `step` remain available. Other native
Steps have an empty `context` unless they override the hook. This uses ordinary compiled execution;
it does not add a JSON runner or change the lifecycle in #1670.

### Logical model outputs

`model_output::<T>(name, result_pointer, criterion)` declares a typed model proposal by a local name.
Native build finds the unique result-to-State binding at that pointer and adds its field/criterion
to the model template. Export includes the same resolved criteria; reusable builders retain unresolved
declarations in `data.model_outputs` until their destinations are bound.
Direct result pointers and equivalent chained `.at(...)` selectors resolve to the same model output.
Native execution retains a typed codec for `T: Value + Serialize + JsonSchema`. The caller
must provision that concrete State type; the model cannot propose undeclared fields. For example:

```rust
let step = StepBuilder::new()
    .with_model(model_template) // Do not separately declare the same State-update destination.
    .model_output::<u64>("count", "", "Return the count")
    .action_with_config("increment", (), |context, _, &()| {
        Ok(context.proposed::<u64>("count")? + 1)
    })
    .result::<u64>()
    .update("caller_counter", "")
    .next("done")
    .build()?;
```

Actions read `count` regardless of the bound destination. Missing/invalid proposals fail before
actions. Final results still pass the result schema and the destination's native decoder before
the existing atomic turn commit. A model output needs exactly one matching State destination;
missing, ambiguous, and duplicate model destinations fail build. This does not change native
TurnProposal routing or introduce a separate model executor.

## Export Step configuration

`StepBuilder` builds native Steps. Both the builder and built `ConfiguredStep` provide `.to_json()`
and `data_contract()`. The concrete built type is public for these inspection methods and implements
the ordinary `Step` trait; it adds no separate executor or authoring object. JSON contains configuration only.

```rust
let builder = StepBuilder::new()
    .bind_state("count", "count")
    .action_with_config("increment", 1_u64, |context, _, amount| {
        Ok(context["count"].as_u64().ok_or("invalid count")? + amount)
    })
    .update("count", "")
    .next("done");
let saved = builder.to_json()?;
let step = builder.build()?;
assert_eq!(step.to_json()?, saved);
```

`.action_with_config(name, settings, callback)` keeps the ordinary Rust callback and exports the
explicit capability name/settings. The callback receives the same typed settings as its third
argument. No name lookup happens during native execution. The future JSON runner must provide an
implementation for that name; exporting configuration does not serialize Rust code. Settings must
contain configuration, not credentials or runtime handles.

`.operation_with_config(name, settings, operation)` starts with a typed context/result operation and
exports the same reference/settings. The operation receives `&context` and `&settings`.

`.action_named_with_config(result, name, settings, callback)` additionally saves the action's result
for later actions and bindings, exactly like `.action_named(...)`.

| Field | Exported configuration |
| --- | --- |
| `version` | Configuration format version, currently `1`. |
| `wiring` | Description, bindings, native destination routing, and summary. |
| `data` | Named argument schemas/presence, optional result schema, and logical model-output schemas/criteria. |
| `input` | Static `InputSpec` (`{kind: "static", specification: {ui, schema}}`) or explicit input factory reference. |
| `model` | Goal, next-Step criteria, resolved State-update criteria, and restore permission from `ModelTemplate`. |
| `finalization` | Initial result source (`context` or a proposed State field) and ordered action references/settings with optional saved result names. |

Rust-built input specifications retain their typed decoders during execution. Exporting them does not
normalize the native Step to JSON codecs. Native State is likewise caller-owned and remains typed.

For a dynamic pure input factory, `.with_input_factory_config(name, settings, factory)` exports the
reference and settings and calls the supplied Rust factory directly. The factory receives `&Scope`
and `&settings` and returns `Result<InputSpec, FlowError>`.

Opaque `.action(...)`, `.operation(...)`, input factories, and custom context preparation cannot be
serialized. They remain valid Rust components; `.to_json()` returns an explicit error instead of
silently omitting behavior. Names supplied for export must be nonblank. Build and export both reject
duplicate/blank action-result names, unknown action-result bindings, and model-response bindings
without a model. Export never invokes actions or input factories.

`StepConfiguration` can be deserialized to inspect or store JSON data. It has no execution/build
method. The [configured FlowBuilder work](https://github.com/lyquor-labs/lyquor/issues/1656) consumes
these native `StepBuilder<C, O, I>` contracts. Flow entry/exit selection and State initialization stay
in that workstream.

## Collect input

Build an `InputSpec` directly with `lyquid_flow::InputSpec::builder()` and pass it to `with_input`.
The field declarations provide typed decoders and validation; the layout supplies the input UI:

```rust
use lyquid_configured_step::StepBuilder;
use lyquid_flow::InputSpec;

let mut input = InputSpec::builder();
let message = input.field("message", "Your question", String::new())
    .non_blank()
    .text_input();
let submit = input.submit("Send");
let layout = input.ui().column(vec![message, submit]);
let input_spec = input.finish(layout)?;

let step = StepBuilder::new()
    .with_input(input_spec)
    .update_from("message", lyquid_configured_step::ValueSource::Input { name: "message".into() })
    .summary("Received a message")
    .build()?;
```

The containing Flow declares a `String` State field named `message`; the binding stages its replacement
after successful input validation. A helper returning `InputSpec` is optional when reusing a form.
Multi-field submissions retain Flow's atomic validation. Clients can receive the spec's serialized
UI and schema. To load the same UI/schema with JSON field decoders, use
`let input_spec: InputSpec = serde_json::from_str(input_json)?;` and pass it to the same `with_input`.

`with_input_factory(|scope| ...)` builds presentation from read-only Scope.
`with_fallible_input_factory` supports presentation that can fail, such as a State-based prompt template.
Both factories must be pure and deterministic: they run for presentation, model preflight when a model
is configured, and finalization. `with_input(spec)` uses the same path by cloning its spec.
A factory failure publishes no input and rejects the turn without an action or model call.

Omit `with_input` to run without input collection, and bind arguments to sources available in that
configuration. To create optional variants, clone a base builder and attach input only to the variant
that needs it. Factories and retained decoders remain runtime objects rather than serialized wiring.

## Define actions

Append supplied units with `.action(unit)` to configure finalization behavior alongside the wiring.
Application callbacks receive ordinary data rather than mutable Scope, State updates, or turn proposals.
The adapter selects proposed values internally through Flow's existing typed accessors.

### Ordered action chains

Rust callbacks read prepared arguments, the model response, and named earlier outputs through
`ActionContext`. Whole-Step bindings supply arguments and commit results; actions own any further
data transformations.

Finalization is an ordered chain of actions. `new()` starts with the prepared JSON context as the
initial result; typed Rust callers can instead start with `operation` or `proposed`.
Each `.action(unit)` receives the previous result and returns the input for the next action. All
actions share the same prepared context. Formatters and JSON decoders are ordinary supplied action
units and run at their declared position in the chain.
Only the last result supplies Result bindings and result-based routing. Trace templates can also read
prepared context, the model response, and named action outputs.

```rust
let step = StepBuilder::new()
    .with_input(input_spec)
    .with_model(model_template)
    .action(action1)
    .action(formatter)
    .action(action2)
    .update("selection", "")
    .next("done")
    .summary("Selected {{ result.name }}")
    .build()?;
```

Action functions have the shape `fn(&ActionContext<'_, Context>, PreviousResult) -> Result<NextResult, String>`.
The context dereferences to the prepared arguments for convenient field access; `prepared()` explicitly
returns those arguments. `model_response()` borrows the complete original `lyquid_llm::ModelResponse`.
`result(name)` reads a named earlier output. These values are independent of the previous result.
Their result types may differ. Declaration order is execution order; actions do not run concurrently.
The first error prevents all later actions and rejects the turn. State bindings and trace commit only
after every action succeeds. External effects already performed by earlier actions cannot be rolled back.

### Temporary model response and named outputs

Flow retains the original response during `Step::finalize`; handwritten Steps read
`scope.model_response()`. Configured actions read it through `context.model_response()` at any position.
The response is read-only, absent when no model ran, and excluded from Scope clones and checkpoints.
The runner clears it on success or failure. Each action chain also starts with an empty named-result map.

```rust
let step = StepBuilder::new()
    .with_model(model_template)
    .action(|_, _| Ok("unrelated first result"))
    .action_named("formatted", |context, _| {
        let response = context.model_response().ok_or("missing model response")?;
        serde_json::from_str::<serde_json::Value>(response.text.as_deref().ok_or("missing text")?)
            .map_err(|error| error.to_string())
    })
    .action(|_, _| Ok(()))
    .action(|context, _| {
        let saved = context.result("formatted").ok_or("missing formatted result")?;
        Ok(saved.clone())
    })
    .proposed_next()
    .build()?;
```

A formatter is supplied by an action crate; the inline parser only illustrates the data handoff.
Raw text still contains Flow's `advance`/`restore` response envelope, which Flow validates before
finalization. This API does not introduce domain model requests or an alternative response parser.

Bind saved values with `ValueSource::ActionResult { action: "formatted".into(), pointer: "/updates/answer".into() }`.
Model-response bindings select paths such as `/text`, `/usage/total_tokens`, `/sources`, `/raw_json`, and
`/http/status`. Optional metadata serializes as null; finish reasons serialize as `stop`, `length`,
`tool_calls`, `content_filter`, or `{"other":"provider_reason"}`.
Only explicit State bindings or trace templates persist selected data. Named outputs are saved only
after their action and output serialization succeed; a failure stops the chain and rejects the turn.

### Operations and context preparation

`StepBuilder::operation` runs application-owned retrieval, deterministic processing, or fixtures in
finalize. `action` composes transformations or a formatter without another Step implementation:

```rust
let builder = StepBuilder::operation(|context: &Context| Ok(context.count))
    .action(|_, count| Ok(Context { count: count + 1 }));
```

By default the builder decodes Context-targeted bindings directly into the callback's context type.
`with_context` decodes a separate type `I` and prepares `Context` from it. Action callbacks borrow
those arguments through `ActionContext`; `operation` still receives `&Context` directly. Binding
targets name fields of `I`, while Context sources and the summary read prepared `Context`.

Preparation must be pure and deterministic. A model-backed step evaluates preparation before the
model call to validate Context-to-State bindings, then again during finalize. Input presentation must
also be pure. Keep side effects in operations; there is no context/result cache on shared Steps.

### Model actions

Attach Flow's existing `ModelTemplate` with `with_model`. The exported JSON `model` object describes
the same goal, next-step criteria, and State-update criteria. Scope renders the template, calls its model,
validates the response against the declared destinations/State fields, and passes the resulting
`TurnProposal` to finalize. Model calls retain the existing usage reporting and error handling.

Select a typed proposed State replacement with `StepBuilder::proposed`, then compose processing:

```rust
use lyquid_flow::ModelTemplate;

let template = ModelTemplate::new(
    "Increment {{ state.counter }}",
    vec![(Some("done".into()), "When complete".into())],
    vec![("counter".into(), "The incremented count".into())],
);
let step = StepBuilder::<serde_json::Value, u64>::proposed("counter")
    .action(|_, count| Ok(Context { count }))
    .with_model(template)
    .proposed_next()
    .update("counter", "/count")
    .summary("Count {{ result.count }}")
    .build()?;
```

The selected field must exist in State with the requested Rust type and be declared in the model's
update criteria; those checks precede the model call. If the model omits that replacement, finalization
fails rather than silently reading the old committed value. The result can be formatted, validated,
or normalized through `action` before State bindings consume it.

Model templates use prepared `context` alongside Flow's `state`, `input`, `trace`, and `step` variables.
Optional JSON parsing and schema
validation are supplied by the [JSON formatter action](../steps/actions/json_formatter/README.md).
It runs during finalize and does not replace Flow's model-response parser or modify model requests.

Without custom processing, use `StepBuilder::new()`
and configure no result bindings. Model-proposed State updates are retained. Configured
bindings override the fields they target; `proposed_next()` retains the model-selected destination,
while fixed or result routing deliberately overrides it during finalize. These changes commit together.

### Ordinary formatters and optional work

Supply a formatter through `.action(formatter)` just like every other unit. Its implementation owns
template/schema validation and output decoding; validate static configuration when constructing the
unit. The builder controls ordered execution and whole-step bindings. For JSON text, use the concrete
formatter action:

```rust
use lyquid_json_formatter::{JsonFormatterConfig, json_formatter};

let step = StepBuilder::operation(|_: &serde_json::Value| Ok(r#"{"count":8}"#.to_owned()))
    .action(json_formatter(JsonFormatterConfig::new())?)
    .update("count", "/count")
    .next("done")
    .build()?;
```

Its schema configuration belongs to the action crate. `model_response_json_formatter` reads the
original response from `ActionContext` independently of the previous result and returns parsed JSON.
Attach it with `.action_named("formatted", model_response_json_formatter(config)?)` to retain that
output for later actions. They can read both `context.model_response()` and `context.result("formatted")`.
Final bindings select `ModelResponse` or `ActionResult` sources; no wrapper result needs to be passed
through intervening actions. See [temporary context](#temporary-model-response-and-named-outputs).

No configured actions means no custom finalization work. No input specification means no input collection;
no model template means no model call. There are no explicit bypass controls. The runtime still
applies bindings and routing, renders the trace, and validates/commits the turn. A base builder can be
cloned before attaching optional components to construct different variants.

## Handle execution and failures

`build()` checks static wiring before returning a Step. `ConfiguredStep` follows **input → model → finalize → validate/commit**:

1. Flow collects and validates optional `InputSpec` input.
2. With a model attached, the adapter prevalidates wiring, prepared context, and action requirements.
   It returns `TemplateSpec::Template` only when preflight succeeds. Flow executes and decodes the model
   call. Without a model, the adapter returns `TemplateSpec::Skip`.
3. For an Advance proposal, finalize prepares context, runs each action in declared order, revises the
   proposal with bindings and routing, and renders the trace. Existing proposed updates survive unless
   a binding replaces them. Fixed and result-based routing exclude restores from the model response
   contract and reject restore proposals before actions. With `proposed_next()` and an allowing model
   template, restores pass through unchanged, skipping actions, bindings, routing, and summary rendering;
   Scope validates the checkpoint and restores it without adding a trace entry.
4. Scope validates and commits through its unchanged runtime path.

The `model_template` hook cannot return errors. Failed preflight returns `Skip` to prevent a billed
call, and the same pure preparation reports the error through finalize. No mutable Step cache,
additional runtime output type, or second executor is used.

An action, model, processing, decoding, routing, or trace-rendering error rejects the whole turn without
committing State, cursor, Trace, or new checkpoints. External effects cannot be rolled back. Retry is
caller-owned; submitted input may need resubmission. Invalid constants, prepared Context-to-State
values, and summary syntax are rejected before external work. Preflight also verifies that decoded
State replacements preserve the destination's concrete Rust type, including custom `Value` codecs.
Data-dependent errors remain in finalize.

A restore-only response does not contain an advancing result, so deterministic routing rejects it
rather than silently advancing without required output. This model restriction does not affect explicit
application calls to `Scope::restore`. Model State writes are restricted by `ModelTemplate` declarations
and typed response decoding; configured finalization does not add an independent field allowlist.

For fixtures, supply a typed operation result or script a `TurnProposal` at the model boundary and
retain the configured finalizer. Run through Scope to exercise the ordinary commit path.

## Examples and implementation

[Data-contract tests](tests/data/mod.rs) prove reuse across caller State layouts: nested projections
preserve native `u64` values, data-only input factories derive presentation from bound arguments,
model prompts retain literal data, and logical model outputs follow caller result bindings without
changing actions. They also compare builder/built exports and test atomic argument/result failures.
[Static input tests](tests/data/static_input.rs) distinguish construction-time schema checks from
value-dependent runtime checks. These fixtures cover the Step prerequisite in
[#1679](https://github.com/lyquor-labs/lyquor/issues/1679); Flow-owned invocation arguments, State
initialization, and exit outputs remain [#1656](https://github.com/lyquor-labs/lyquor/issues/1656).

[Composition tests](tests/composition/mod.rs) exercise typed operations, flat bindings, atomic input,
State commits, model usage, child Flows, and checkpoints. The implementation separates declarative wiring
in [wiring.rs](src/wiring.rs) and [next.rs](src/next.rs), the public builder in
[builder.rs](src/builder.rs), private execution composition in [action.rs](src/action.rs), and the runtime
adapter in [step.rs](src/step.rs).
