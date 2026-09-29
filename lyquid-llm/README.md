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
