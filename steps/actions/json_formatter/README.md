# JSON formatter action

`lyquid-json-formatter` parses JSON text and optionally validates it against a JSON Schema.
Use `json_formatter` for a preceding action's String result, or `model_response_json_formatter`
to read the original model response from temporary action context. Both return `serde_json::Value`.
Formatting is optional: attach the action only when parsed JSON is needed.

## Quick start

```rust
use lyquid_configured_step::StepBuilder;
use lyquid_json_formatter::{JsonFormatterConfig, json_formatter};
use serde_json::{Value, json};

let config = JsonFormatterConfig::json_schema(json!({
    "type": "object",
    "properties": {"count": {"type": "integer", "minimum": 1}},
    "required": ["count"],
    "additionalProperties": false
}));

let step = StepBuilder::operation(|_: &Value| Ok(r#"{"count":8}"#.to_owned()))
    .action(json_formatter(config)?)
    .update("count", "/count")
    .next("done")
    .summary("Count {{ result.count }}")
    .build()?;
```

Declare `done` and a compatible `count` State field in the Flow. The operation returns a JSON
string, the formatter validates it, and the `/count` binding saves `8` to State. Use your own
text-producing operation in place of the example. To accept JSON without a schema, use
`json_formatter(JsonFormatterConfig::new())?`. To keep plain text, omit the formatter.

## Format the shared model response

`model_response_json_formatter` reads `context.model_response()`, so it can appear anywhere in
finalization. It ignores the previous action's result. The original response, including text, usage,
sources, provider JSON, HTTP response, web-search flag, and finish reason, remains available unchanged.

Save the formatted value with `action_named` so later actions can read it after intervening results:

```rust
use lyquid_configured_step::{StepBuilder, ValueSource};
use lyquid_flow::ModelTemplate;
use lyquid_json_formatter::{JsonFormatterConfig, model_response_json_formatter};

let template = ModelTemplate::new(
    "Produce an answer",
    vec![(Some("done".into()), "When complete".into())],
    vec![("answer".into(), "The numeric answer".into())],
);
let step = StepBuilder::new()
    .with_model(template)
    .action(|_, _| Ok("an unrelated first result"))
    .action_named("formatted", model_response_json_formatter(JsonFormatterConfig::new())?)
    .action(|_, _| Ok(()))
    .action(|context, _| {
        let raw = context.model_response().ok_or("missing model response")?;
        let formatted = context.result("formatted").ok_or("missing formatted result")?;
        // Both remain readable regardless of the immediately preceding result.
        Ok((raw.sources.clone(), formatted.clone()))
    })
    .update_from("answer", ValueSource::ActionResult {
        action: "formatted".into(), pointer: "/updates/answer".into(),
    })
    .update_from("raw_reply", ValueSource::ModelResponse { pointer: "/text".into() })
    .next("done")
    .summary("Answer {{ actions.formatted.updates.answer }}")
    .build()?;
```

Declare compatible `answer` and `raw_reply` State fields and the `done` destination. Flow still
parses its `advance`/`restore` envelope before finalization; the raw text and any formatter schema
cover that complete envelope. For example, an advance response contains
`{"type":"advance","next":"done","updates":{"answer":42}}`. This action does not change the model
request or replace Flow's parser. Configured Steps skip forward actions for restore proposals.

For domain JSON stored as a String inside a model-proposed field, start with
`StepBuilder::<serde_json::Value, String>::proposed("reply")`, attach a template declaring that
String field, and use `.action_named("formatted", json_formatter(config)?)` instead.

Raw responses and saved outputs last only for the current finalization. State bindings and trace
templates persist only the selected values. Model-response binding paths include `/text`,
`/usage/total_tokens`, `/sources`, `/raw_json`, and `/http/status`. Saved formatted output uses
`ValueSource::ActionResult { action, pointer }`. See the
[temporary context guide](../../../lyquid-configured-step/GUIDE.md#temporary-model-response-and-named-outputs).

## Configuration

`JsonFormatterConfig` has one optional field:

| Field | Meaning | Default |
| --- | --- | --- |
| `schema` | JSON Schema used to validate the parsed value. | Accept any complete JSON value. |

The configuration supports Serde, so applications can save and load it:

```rust
let config: JsonFormatterConfig = serde_json::from_str(saved_config)?;
let formatter = json_formatter::<serde_json::Value>(config)?;
```

Example saved configuration for JSON text containing domain data:

```json
{
  "schema": {
    "type": "object",
    "properties": {
      "products": {"type": "array", "items": {"type": "string"}},
      "summary": {"type": "string"}
    },
    "required": ["products", "summary"],
    "additionalProperties": false
  }
}
```

An empty configuration `{}` accepts any JSON value. Unsupported schema keywords and invalid
references fail when constructing the action. Supported constraints include types, object properties,
required fields, arrays, enums/constants, numeric and string bounds, patterns, document-local
references, and schema composition. Formatter schema validation stops with an error after 128 nested
evaluations, including within alternatives, negation, and conditions. This limit does not apply to
Flow input validation.

For an editor, `schemars::schema_for!(JsonFormatterConfig)` describes the configuration fields.
The configured schema describes the parsed JSON and can guide binding paths such as `/products`
and `/summary`. Applications resolve the saved configuration to an action; this crate supplies no
JSON action registry or input/output binding layer.

## Action inputs and outputs

Both factories return a cloneable callback with the ordinary action signature
`Fn(&ActionContext<'_, Context>, PreviousResult) -> Result<serde_json::Value, String>`.

| Factory | Data source | Output |
| --- | --- | --- |
| `json_formatter(config)?` | The previous result, a `String` containing JSON. | Parsed JSON value. |
| `model_response_json_formatter(config)?` | The original response in `context.model_response()`; ignores the previous result. | Parsed JSON value. |

Attach either with `.action(...)` or `.action_named(name, ...)`. A named output remains readable
through `context.result(name)` and named-result bindings even when later actions return other values.
Ordinary Result bindings and result-based routing use the last action's output.

## Accepted input and errors

The formatter accepts a complete JSON document, with optional surrounding whitespace or one complete
Markdown backtick fence (with no language tag or exactly the `json` tag). The opening fence uses
three or more backticks and must end with a newline before the JSON body. The closing fence must
be on its own line, with at least as many backticks as the opening, up to three leading spaces,
and optional trailing whitespace. LF and CRLF line endings are supported. Objects, arrays,
strings, numbers, booleans, and `null` are supported when allowed by the configured schema.

Unsupported schemas and reference cycles that never descend into a child value fail when constructing
the action.
Malformed JSON, extra prose, incomplete fences, and schema mismatches return an error. The
model-response formatter also rejects absent responses, missing text, and `FinishReason::Length`.
It does not repair or retry invalid output. A failed action stops the chain and prevents the turn's
State, routing, Trace, and checkpoint commit; earlier external effects cannot be rolled back.
