# Building Steps

Use [StepBuilder](../lyquid-configured-step/README.md) to configure your own Steps from an optional `InputSpec`,
an optional `ModelTemplate`, ordered actions, and data bindings. Compose those Steps into
[Flows](../flows/README.md).

The LDK's focus is easy Step and Flow configuration, supported by reusable actions. A large catalog of prebuilt
Steps and Flows is not a product goal. Domain examples can keep contracts specific to their applications.

- [Actions](actions/) provide reusable behavior for custom Steps, starting with the
  [JSON formatter](actions/json_formatter/README.md).
- [Input examples](inputs/README.md) show native input configuration in Rust and JSON.
- [Step examples](examples/) illustrate domain implementations. The
  [refinement Step](examples/refinement-step/README.md) supports the refinement loop Flow and may share its specific
  State and decision contracts.
