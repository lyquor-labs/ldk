# Flow runtime

`lyquid-flow` owns workflow graphs, the `Step` contract, typed input contracts, model-turn execution,
State, Trace, and checkpoint commitment. Steps supply proposals; Scope validates and commits them.

`InputSpec` can be built in Rust or deserialized from its JSON `{ ui, schema }` representation.
JSON loading checks the native UI structure and supported schema, and retains JSON value decoders.
Submissions are schema-validated and bound atomically. Rust-built specs retain their original typed
codecs; JSON-loaded fields are read as `serde_json::Value` and can feed structured-step typed bindings.

For fluent construction, declarative bindings, and typed processing without a handwritten Step implementation, use the optional
[lyquid-structured-step](../lyquid-structured-step/README.md) authoring crate. The runtime does not depend on it.

External Step implementations can use read-only `State::get_value` and `Scope::get_value` to work
with existing value codecs without exposing the backing maps. `Scope::validate_next` preflights a
destination before model or operation effects. These APIs do not commit State or bypass final turn
validation. The existing model phase retains its request execution, proposal decoding, and usage reporting.

`ModelTemplate::allow_restore` controls whether the model response contract offers checkpoint restoration
and whether the parser accepts it. Native templates allow restores by default. Structured Steps disable
them when routing is fixed or selected by an action result. Application-driven `Scope::restore` is independent.

`State::to_json()` projects committed field values as a JSON object for read-only templates and inspection,
without field descriptions or in-flight updates. Field codecs must encode valid JSON; projection errors
are returned to the caller. Model prompts and structured-step trace summaries use this same projection.

`Step::model_context` supplies optional Step-local data to model templates as `context`; existing
Steps receive an empty object by default. Scope resolves it after interactive input validation and
before sending a model request. The goal and every criterion render once with that data alongside
`state`, `input`, `trace`, and `step`. The hook must be pure, and errors reject the turn before the model
or finalization runs. Structured Steps use it to expose their validated, prepared data arguments.
