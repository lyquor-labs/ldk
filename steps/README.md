# Building Steps

Implement the native `Step` contract for input, model work, finalization and summaries. Use
[StructuredSpec](../lyquid-structured-builder/README.md) to add declarative State updates and next-Step
selection, then compose the Steps into [Flows](../flows/README.md).

The LDK's focus is easy Step and Flow configuration, supported by reusable actions. A large catalog of prebuilt
Steps and Flows is not a product goal. Domain examples can keep contracts specific to their applications.

- [Actions](actions/) provide reusable behavior for custom Steps, starting with the
  [JSON formatter](actions/json_formatter/README.md).
- [Input examples](inputs/README.md) show native input configuration in Rust and JSON.
- [Step examples](examples/) illustrate domain implementations. The
  [refinement Step](examples/refinement-step/README.md) supports the refinement loop Flow and may share its specific
  State and decision contracts.
