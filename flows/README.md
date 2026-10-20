# Building Flows

Flows connect Steps and child Flows, define entry points and exits, and carry data between turns. Build your own
with the [Flow runtime](../lyquid-flow/README.md) and [structured Steps](../lyquid-structured-step/README.md).

The LDK focuses on making custom Step and Flow configuration easy, with reusable
[actions](../steps/actions/) supplying behavior. The Flows in this directory are examples of composition;
growing a large catalog of general-purpose Flows is not a product goal.

The [refinement loop](refinement-loop-flow/README.md) demonstrates model-driven refinement and input collection.
Its [refinement Step](../steps/examples/refinement-step/README.md) may use contracts specific to this loop.
