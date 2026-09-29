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

The runner starts a single-node localnet, deploys the app, and serves <http://127.0.0.1:8080/>.
Press Ctrl-C to stop it. Without `MODEL_PROVIDER`, it chooses OpenAI when `OPENAI_API_KEY` is set, otherwise Gemini.

- In the monorepo, existing `target/debug` tools are reused; missing tools are built. Set `REBUILD_TOOLS=1` after
  changing the native node or Shaker.
- In the standalone LDK, run `./lyquid-examples/shopping-assistant/scripts/run.sh` and install `lyquor` and `shaker`
  on `PATH`. Native tool rebuilding is only supported in the monorepo.
- Set `LYQUOR_BIN_DIR` in either layout to use prebuilt tools instead of local builds or `PATH`.

## Search and refine

```text
shopping request
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
product links and retrieved sources let users check them.

- **Continue refining:** enter a preference or requirement; the suggested question is only a hint. This reranks the
  current product set without searching again. Relaxed requirements can bring back excluded products.
- **New candidates:** use the same text bar to request another search, preserving the current goal and accumulated
  search feedback. The parent Flow collects feedback before returning to aggregation.
- **Search:** submit a new request to replace the current search with a fresh Scope.

Both feedback actions submit the choice and message in sequence; Enter continues refinement. If only feedback delivery
fails, the draft remains and **Send** retries it. Users compare products by opening their links; selection and payment
are outside this example. **Finish with no matches** is available only when the ranking is empty.

## History and recovery

The **States** tree records the initial results and each completed refinement or replacement search. Click a node to
restore it without repeating model calls; select its parent to undo. Refining from an earlier node creates a new branch
and preserves existing revisions.

Each search is one Scope, checkpointed at the choice step before collecting feedback. The service stores Scopes by
`Scope::execution_id()` and uses `run_until_input()` and `restore()` directly. Only the HTTP display view and history
labels/parent links live outside Scope; restoration reads State and input from the checkpoint. Input and restore
requests are rejected while execution is in progress.

Start a search with `POST /api/scopes`, then poll `GET /api/scope?id=<scope_id>`. All actions use the returned string
`scope_id`; there is no separate session ID. History responses contain `revisions` and `active_revision_id`.
To restore a revision, send `scope_id` and
`revision_id` to `POST /api/revisions/switch`.

Failed model turns create no history node. Restore a previous node to retry, or start a new search if none exists;
there is no automatic retry. This example still hosts one active search globally, not one per user. Replacing it
removes the old Scope and display view and requests a cooperative stop; an in-flight model call is not interrupted,
but its late result is discarded. Requests for a removed Scope return 404. Idle Scopes have no blocked worker.
There is no automatic expiry, history limit, authentication, or UI recovery after a node restart.

## Use without the web service

```rust
use shopping_assistant::{ProductSearch, ShoppingRequest, flow, initial_state};

let search = ProductSearch::new("openai", &api_key, "")?;
let flow = flow(move |context, round| search.search(context, round));
let state = initial_state(ShoppingRequest::new("A coffee maker for travel"))?;
```

Bind the Flow and State to a `Scope` with your `ModelConfig`. Call `run_until_input()` to obtain an `InputSpec` and
the requesting Scope's committed State. Submit a JSON field object through
`scope.input_handle().submit_input()`, then call `run_until_input()` again. Use `spec.field_schema()` to
identify the action or feedback field. Blocking `advance()` consumes input through the same handle. The search closure can use a custom
backend or deterministic test data; credentials stay outside model-visible State.
