# Structured Flow builder

`StructuredFlowBuilder` composes typed `StructuredStepBuilder`s and returns an ordinary
`lyquid_flow::Flow` from `.build()`. The builder stays in `lyquid-structured-flow` and exports the
authored configuration with `.to_json()` before build. Callers supply State and runtime services
through `lyquid_flow::Scope`. Configuration export can fail for opaque native callbacks.

```rust
use lyquid_structured_flow::{StructuredFlowBuilder, StructuredStepBuilder};
use lyquid_flow::{AutoCheckpointConfig, Scope, State};

let builder = StructuredFlowBuilder::new("counter")
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
let initial = State::builder().field("count", "Current count", 7_u64).build()?;
let mut scope = Scope::new(flow.into(), initial, AutoCheckpointConfig::Disabled, None);
scope.advance()?;
assert_eq!(scope.state().get::<u64>("count"), Some(&8));
```

Graph routes come from each Step's fixed, result-based or model-proposed successor. Build/export checks
entry, exits, duplicate nodes and known destinations without running callbacks or models.

Following the [three-layer design](https://docs.superhuman.com/d/Lyquid-Flow_dEIF_s98LeI/Implementation-Items_suwN_toU),
structured construction stays above the core Flow/Step execution contract. Native `lyquid-flow`
builders and custom Steps remain available for advanced composition.

JSON export contains authored graph declarations and Step configurations. Its Rust representation
is internal; `.to_json()` is the public export API. The design's Configurable
Flow layer additionally requires declarative construction through configurable Steps and recursively
configurable subflows; that capability and the proposed `ConfigurableStep` contract belong to #1673.
Export alone does not provide it. Opaque Rust callbacks can run natively but return an explicit export
error.

See [GUIDE.md](GUIDE.md) for graph validation and export behavior.
