# lyquid-llm

`lyquid-llm` helps Lyquid instance functions call LLMs through OpenAI-compatible and Gemini backends.
It handles endpoint and authentication setup, request and output formats, and response parsing into
shared types for generated text, finish reasons, and token usage. Enable the `ldk` feature to send
requests with `call_model` through Lyquid's HTTP API.

Supply your API key and build a model configuration:

```rust
use lyquid_llm::ModelConfig;

let model = ModelConfig::gemini("gemini-2.5-flash", api_key)
    .json_mode()
    .build()?
    .max_output_tokens(8192);
```

With the `ldk` feature enabled, send a prompt from a Lyquid instance function:

```rust
use lyquid_llm::ModelRequest;

let request = ModelRequest::new(model.model(), "Return a JSON object with a greeting field.");
let response = lyquid_llm::call_model(&model, &request)?;
if let Some(text) = response.text {
    lyquid::println!("{text}");
}
```

`build()` creates the configuration; `call_model()` sends the request and parses the response.
`response.text` contains the generated text when available, and `response.usage` contains any reported token usage.

When web search is enabled on the backend, `response.web_search_used` reports search usage, and
`response.sources` contains the reported source URLs.

## Cumulative token usage

`Usage::accumulate` adds provider-reported token counts. `UsageTotals` pairs a `Usage` value with
`call_attempts` when call counting is also needed; it does not define a second set of token fields.
Its JSON representation keeps `call_attempts`, `input_tokens`, `output_tokens`, and `total_tokens` together.

With the `ldk` feature, attach a usage observer once and use `UsageTracker` to share an
application-defined ledger across call sites:

```rust
use lyquid_llm::{UsageTotals, UsageTracker, with_usage_observer};

#[derive(Clone, Default)]
struct SessionUsage {
    draft: UsageTotals,
    review: UsageTotals,
}

let tracker = UsageTracker::<SessionUsage>::default();
let draft_recorder = tracker.clone();
let draft_model = with_usage_observer(model, move |usage| {
    let current = draft_recorder.record(|state| state.draft.record(usage));
    let total = current.draft.combined(&current.review);
    lyquid::println!("draft usage: {total:?}");
});
let response = lyquid_llm::call_model(&draft_model, &request)?;
let current = tracker.snapshot();
```

`call_model` invokes attached observers once per attempt, including failures during request preparation,
HTTP transport, and response parsing. Observers receive provider usage before application output validation;
failed calls and responses without usage report `None`. Direct `prepare_request` and `parse_response`
calls do not notify observers. `ModelConfig` forwards notifications, and nested observers each run once,
starting with the wrapped backend. Attach each accounting operation once; if Flow already reports the
same calls through `Scope::on_usage`, do not also count them with a backend observer.

Each `UsageTotals::record` increments `call_attempts`, including failed attempts without reported usage. Missing token fields
make the corresponding cumulative field unknown (`None`, serialized as `null`). Provider totals are summed as
reported, independently of input and output counts. `combined` sums disjoint groups without changing either source.
`UsageTracker::record` applies the application's update and clones the resulting state under one lock;
`snapshot` clones without modifying it. Only the update changes counters, so setting session metadata does not
itself count as a model call. Keep updates short and synchronous, and perform model calls and logging outside them.
Cloning a tracker shares the ledger; creating a new tracker starts an independent ledger. Keep it outside
restorable Flow State and capture clones in observers so restoring a checkpoint preserves incurred usage.
The application defines categories and attaches observers; subsequent model calls need no manual accounting.
