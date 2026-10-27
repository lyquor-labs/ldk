# JSON formatter

`lyquid-json-formatter` parses JSON text and optionally validates it against a JSON Schema.
Use the function returned by `json_formatter` to parse text, or pass `Scope::model_response()`
to the function returned by `model_response_json_formatter`. Both produce `serde_json::Value`
and can be called from a native Step's `finalize` method.

## Quick start

```rust
use lyquid_json_formatter::{JsonFormatterConfig, json_formatter};
use serde_json::json;

let config = JsonFormatterConfig::json_schema(json!({
    "type": "object",
    "properties": {"count": {"type": "integer", "minimum": 1}},
    "required": ["count"],
    "additionalProperties": false
}));

let format = json_formatter(config)?;
let value = format(r#"{"count":8}"#)?;
assert_eq!(value["count"], 8);
```

To accept JSON without a schema, use `json_formatter(JsonFormatterConfig::new())?`.
The containing Step chooses which parsed values to write into its `TurnProposal`, along with
the destination and Trace summary. Core validates and commits that proposal.
The [composition tests](tests/composition/mod.rs) show this in a native Step finalizer.

## Format the shared model response

During `Step::finalize`, pass the original response from the Scope:

```rust
use lyquid_flow::{FlowError, Scope};
use lyquid_json_formatter::{JsonFormatterConfig, model_response_json_formatter};
use serde_json::Value;

fn read_model_result(scope: &Scope) -> Result<Value, FlowError> {
    let format = model_response_json_formatter(JsonFormatterConfig::new())?;
    format(scope.model_response())
}
```

The formatter borrows the response, preserving its text and metadata. Core parses its
`advance`/`restore` envelope before finalization, so the formatter sees that complete envelope.
For example, an advance response contains
`{"type":"advance","next":"done","updates":{"answer":42}}`.

For domain JSON stored as a String inside a model-proposed State update, read that String
from the proposal and pass it to `json_formatter(config)?`. Keep parsed values in ordinary
Rust variables while finalizing, and write the values that should persist into the proposal.

## Configuration

`JsonFormatterConfig` has one optional field:

| Field | Meaning | Default |
| --- | --- | --- |
| `schema` | JSON Schema used to validate the parsed value. | Accept any complete JSON value. |

The configuration supports Serde, so applications can save and load it:

```rust
let config: JsonFormatterConfig = serde_json::from_str(saved_config)?;
let formatter = json_formatter(config)?;
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
references fail when constructing the formatter. Supported constraints include types, object properties,
required fields, arrays, enums/constants, numeric and string bounds, patterns, document-local
references, and schema composition. Formatter schema validation stops with an error after 128 nested
evaluations, including within alternatives, negation, and conditions. This limit does not apply to
Flow input validation.

For an editor, `schemars::schema_for!(JsonFormatterConfig)` describes the configuration fields.
The configured schema describes the parsed JSON, such as its `products` and `summary` fields.

## Function signatures

Both factories return a function that is `Clone + Send + Sync`. Construction and calls can
return `FlowError`; successful calls return `serde_json::Value`.

| Factory | Function argument | Output |
| --- | --- | --- |
| `json_formatter(config)?` | `&str` containing JSON. | Parsed JSON value. |
| `model_response_json_formatter(config)?` | `Option<&ModelResponse>`, usually from `scope.model_response()`. | Parsed JSON value. |

## Accepted input and errors

The formatter accepts a complete JSON document, with optional surrounding whitespace or one complete
Markdown backtick fence (with no language tag or exactly the `json` tag). The opening fence uses
three or more backticks and must end with a newline before the JSON body. The closing fence must
be on its own line, with at least as many backticks as the opening, up to three leading spaces,
and optional trailing whitespace. LF and CRLF line endings are supported. Objects, arrays,
strings, numbers, booleans, and `null` are supported when allowed by the configured schema.

Unsupported schemas and reference cycles that never descend into a child value fail when constructing
the formatter.
Malformed JSON, extra prose, incomplete fences, and schema mismatches return an error. The
model-response formatter also rejects absent responses, missing text, and `FinishReason::Length`.
It does not repair or retry invalid output. Propagating an error with `?` from `Step::finalize`
rejects the turn before Core commits it.
