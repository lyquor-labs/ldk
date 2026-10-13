# Shopping Assistant

`shopping-assistant` searches for products, refines their ranking, and lets users revisit earlier results.
It uses the LDK [refinement loop](../../flows/refinement-loop-flow/README.md); search, provider credentials,
product links, and hosting Scopes belong to this example.

## Run

From the repository root, use either provider:

```bash
OPENAI_API_KEY=... \
  ./ldk/lyquid-examples/shopping-assistant/scripts/run.sh

MODEL_PROVIDER=gemini GEMINI_API_KEY=... \
  ./ldk/lyquid-examples/shopping-assistant/scripts/run.sh
```

The runner starts a single-node localnet, deploys the app, and configures the repository's
[shared Flow page](../../../ui/README.md) at <http://127.0.0.1:8080/>. Install Node.js 22.12+ and npm for the page.
`shaker serve` exposes the Lyquid on port 8081; the shared page's server proxies its Flow HTTP routes.
Press Ctrl-C to stop it. Without `MODEL_PROVIDER`, it chooses OpenAI when `OPENAI_API_KEY` is set, otherwise Gemini.

- In the monorepo, existing `target/debug` tools are reused; missing tools are built. Set `REBUILD_TOOLS=1` after
  changing the native node or Shaker.
- In the standalone LDK, run `./lyquid-examples/shopping-assistant/scripts/run.sh` and install `lyquor` and `shaker`
  on `PATH`. Set `FLOW_UI_DIR` to the shared `ui/` folder in a Lyquor checkout. The LDK's WASM build has no dependency
  on that folder. Native tool rebuilding is only supported in the monorepo.
- Set `LYQUOR_BIN_DIR` in either layout to use prebuilt tools instead of local builds or `PATH`.

## Search and refine

```text
request (InputSpec)
      |
      v
aggregate_candidates <-----------------------------------+
      |                                                  |
      v                                                  |
refine_candidates (LDK loop)                             |
      +-- restart --> restart_feedback (text input) -----+
      +-- finish --> finished
```

Search targets 15–20 distinct, related products, then the LDK loop ranks and filters them. The app checks that the
provider used web search, removes invalid or duplicate results, and keeps at most 20 products. Shortfalls and search
errors are reported without a catalog fallback. Results and prices are model-extracted, not guaranteed inventory;
product links let users check them.

- **Refine:** enter feedback next to the results and click **Refine**. The suggested question is only a hint.
  The action and feedback are submitted together, reranking the current product set without searching again. Relaxed requirements can bring back excluded products.
- **New candidates:** select the restart choice, then submit search feedback, preserving the current goal and accumulated
  search feedback. The parent Flow collects feedback before returning to aggregation.
- **Start over:** start a fresh Scope, then enter the new shopping request through its first input Step.

**Start** creates the execution without business parameters. Its first Step asks for a nonblank shopping request;
submitting that InputSpec saves the request and starts the search. Creation alone does not call a model or search provider.
The shared page shows product results first, followed by the declared feedback field and action buttons.
When search returns no products, aggregation goes directly to search feedback so the user can revise the search.
Only a non-empty candidate set enters refinement. A later refinement may still produce an empty ranking and offer Finish.
**Next step** jumps to the form when the product list is long. It never
carries an answer into a new request automatically. A rejected submission keeps the same-round draft for correction. Users compare products by opening their links; selection and payment are outside
this example. The Finish choice is available only when the ranking is empty.

## Token usage

Run `shaker console <LYQUID_ID>` to read token usage from the hosted example. Each model call attempt emits a line
prefixed with `shopping_token_usage ` followed by JSON:

- `phase`: `search` or `refinement`.
- `usage`: this call's provider-reported `input_tokens`, `output_tokens`, and `total_tokens`; `null` when usage is unavailable.
- `search`, `refinement`, and `total`: cumulative session counters, each containing `call_attempts` and the three token fields.

Shared collection and token accumulation use [`lyquid_llm::UsageTracker` and `UsageTotals`](../../lyquid-llm/README.md).
Attach a search observer to the LLM backend with `lyquid_llm::with_usage_observer`, and a refinement observer
through the existing `Scope::on_usage` hook. Both share the same tracker and report automatically before
application validation; business call sites do not update counters. Search calls `lyquid_llm::call_model`
directly and needs no Scope. The phase is selected when attaching each observer, not inferred from a Flow Step.
These records contain application counters without a Scope ID.
`call_attempts` counts attempted calls, not confirmed billable requests. Missing token fields make the corresponding
cumulative field `null`; provider-reported totals are summed directly, without inferring them from input and output.
Accounting includes the initial refinement and responses that later fail validation. Search and refinement accumulate
across history branches: restoring a checkpoint does not subtract usage, and creating a new Scope starts fresh counters.
Usage is recorded in the console only; the page does not display it.

## History and recovery

The shared **History** tree records the initial results and each completed refinement or replacement search. Click a node to
restore it without repeating model calls; select its parent to undo. Refining from an earlier node creates a new branch
and preserves existing revisions.

The example declares `lyquid_flow::serve_flow!` in [`src/lib.rs`](src/lib.rs). LDK owns the HTTP exports, registry,
request IDs, async worker, history parent links, and restoration. Shopping defines the Flow, input/result presentation,
and business initialization in [`src/lib.rs`](src/lib.rs); it has no `service.rs`, application worker, frontend source,
or asset-copying `build.rs`. Its runner only configures the shared frontend and its upstream.
`replace_existing: true` preserves one active search: a new valid creation retires the old client and requests a
cooperative stop. Initialization failure leaves the previous search intact. Late results cannot recreate a retired client.

The shared HTTP interface is:

- `POST /api/flows` with no body creates an execution and returns `{ "client_id": "..." }`.
- `GET /api/flows/<client_id>` returns status, step, input, view, execution error, and history in one publication.
- `POST /api/flows/<client_id>/input` sends `{ "request_id": "...", "values": { ... } }` to the retained InputSpec.
- `POST /api/flows/<client_id>/restore` with `{ "revision_id": "..." }` restores a checkpoint and schedules the worker.

The application-specific search/history/restore endpoints and the older Scope/action endpoints are removed.
The first input submits `{ "request_id": "...", "values": { "shopping_request": "..." } }`.
`GET /api/flows` and creation schemas are removed; nonempty creation bodies return 400.
Validation errors (422) preserve the form; duplicate or stale rounds return 409 and a
removed client returns 404. The UI keeps failed submissions as drafts. Nonblank feedback and the condition that Finish
is available only with an empty ranking are enforced by InputSpec, including direct HTTP submissions.
Drafts remain bound to their displayed input round: polling the same request preserves them, while a different request
clears the old draft. A lost response triggers a read, never an automatic resubmission. Reload the execution URL
or paste its ID into **Resume a previous session** to reopen it while the service retains it.

[`src/flow/view.rs`](src/flow/view.rs) selects the committed shopping result into `ViewSpec`: product cards, canonical prices
and links, constraints, the next hint, and search context. The parent Flow's view reads the active child Scope while
refinement is running, so the web UI sees the latest committed ranking. The document contains native A2UI components
with native cards, headings, and `openUrl` product links. Retrieved sources remain in the catalog and result metadata,
without a separate Sources list on the page. The optional `ui.data.shopping` projection remains
available to domain consumers and tests; the shared page renders only declared components and never reads that key.
Input choices come from InputSpec;
State, Trace, and credentials are never exported wholesale. There is no separate cached `ScopeView`.
The same file's `shopping_history` callback selects recommendation pages and their display labels. LDK saves the
checkpoint before exposing that page's input, publishes its metadata atomically, and handles branch identities and
restoration. Intermediate text prompts, failed turns, duplicate workers, and restoration create no extra nodes.

Failed model turns create no history node. The text Step may already have committed before the model fails, so
restore a previous choice checkpoint to retry, or start a new search if none exists. Restoring publishes a fresh
request ID without repeating model calls. There is no automatic model retry. This example still hosts one active
search globally, not one per user. There is no automatic expiry, history limit, authentication, or UI recovery after
a node restart.

## Use without the web service

```rust
use shopping_assistant::{ProductSearch, flow, initial_state};
use lyquid_llm::backend::openai_compat::{OpenAiCompatBackend, WebSearchOptions};

let backend = OpenAiCompatBackend::openai(&api_key)?.web_search(WebSearchOptions {
    required: true,
    ..WebSearchOptions::default()
});
let search = ProductSearch::new("gpt-5.4", backend);
let flow = flow(move |context, round| search.search(context, round));
let state = initial_state()?;
```

Bind the Flow and State to a `Scope` with your `ModelConfig`. Call `run_until_input()` to obtain an `InputSpec` and
the requesting Scope's committed State. The first contract collects `shopping_request`; the request is stored as a
String rather than a separate `ShoppingRequest` wrapper. Submit a JSON field object through
`scope.input_handle().submit_input()`, then call `run_until_input()` again. Use `spec.field_schema()` to
identify the declared fields. A refinement submission includes both the action and feedback fields. Blocking `advance()` consumes input through the same handle. The search closure can use a custom
backend or deterministic test data; credentials stay outside model-visible State.
