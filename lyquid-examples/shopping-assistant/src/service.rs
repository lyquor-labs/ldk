use std::sync::Arc;

use lyquid::prelude::*;
use lyquid_flow::{AutoCheckpointConfig, InputHandle, Scope, ScopeId, State};
use lyquid_llm::{
    ModelConfig, OutputFormat,
    backend::{
        gemini::GeminiBackend,
        openai_compat::{OpenAiCompatBackend, ReasoningEffort, Verbosity, WebSearchOptions},
    },
};
use refinement_loop_flow::DecisionState;
use serde::{Deserialize, Serialize};

state! {
    instance active_scope: Option<(ScopeId, InputHandle)> = None;
    instance model_provider: String = String::new();
    instance openai_api_key: String = String::new();
    instance gemini_api_key: String = String::new();
    instance scopes: HashMap<ScopeId, Scope> = new_hashmap();
    instance scope_views: HashMap<ScopeId, ScopeView> = new_hashmap();
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartScopeBody {
    request: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefineBody {
    scope_id: ScopeId,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartBody {
    scope_id: ScopeId,
    feedback: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChoiceBody {
    scope_id: ScopeId,
    choice: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreBody {
    scope_id: ScopeId,
    revision_id: ScopeId,
}

#[derive(Clone, Default, Serialize)]
struct HistoryView {
    active_revision_id: Option<ScopeId>,
    revisions: Vec<RevisionView>,
}

#[derive(Clone, Serialize)]
struct RevisionView {
    id: ScopeId,
    parent_id: Option<ScopeId>,
    name: String,
    kind: &'static str,
    summary: String,
    status: &'static str,
    active: bool,
    search_round: u64,
    candidate_count: usize,
    hard_constraints: Vec<String>,
    soft_preferences: Vec<String>,
}

#[derive(Serialize)]
struct StartedScope {
    scope_id: ScopeId,
    provider: String,
}

/// HTTP display data only. Execution State, input position, and checkpoints belong to Scope.
#[derive(Clone, Serialize)]
struct ScopeView {
    scope_id: ScopeId,
    status: &'static str,
    input_kind: Option<&'static str>,
    request: String,
    hint: String,
    hard_constraints: Vec<String>,
    soft_preferences: Vec<String>,
    aggregation_round: u64,
    restart_feedback: Vec<String>,
    search_summary: String,
    retrieved_sources: Vec<String>,
    candidates: Vec<Product>,
    choices: Vec<ChoiceView>,
    history: HistoryView,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
struct ChoiceView {
    id: String,
    label: String,
}

fn shopping_choices(decision: &DecisionState) -> Vec<ChoiceView> {
    refinement_config()
        .choice_options()
        .into_iter()
        .filter(|choice| choice.id != FINISH_CHOICE || decision.ranking.candidate_ids.is_empty())
        .map(|choice| ChoiceView {
            label: if choice.id == FINISH_CHOICE {
                "Finish with no matches".to_owned()
            } else {
                choice.label
            },
            id: choice.id,
        })
        .collect()
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn err(message: impl Into<String>) -> LyquidError {
    LyquidError::LyquorRuntime(message.into())
}

#[method::instance(export = eth)]
fn is_ready(_ctx: &_) -> LyquidResult<bool> {
    Ok(true)
}

#[method::instance(export = eth)]
fn set_model_api_key(ctx: &mut _, provider: String, api_key: String) -> LyquidResult<bool> {
    let provider = provider.trim().to_ascii_lowercase();
    let api_key = api_key.trim().to_owned();
    if api_key.is_empty() {
        return Err(err("the model API key must not be empty"));
    }
    match provider.as_str() {
        "openai" => *ctx.instance.openai_api_key.write() = api_key,
        "gemini" => *ctx.instance.gemini_api_key.write() = api_key,
        _ => {
            return Err(err(format!(
                "unsupported model provider {provider:?}; use openai or gemini"
            )))
        }
    }
    *ctx.instance.model_provider.write() = provider;
    Ok(true)
}

fn model_setup(
    provider: &str, openai_api_key: &str, gemini_api_key: &str,
) -> Result<(ModelConfig, ProductSearch), String> {
    const OPENAI_MODEL: &str = "gpt-5.4";
    const GEMINI_MODEL: &str = "gemini-2.5-flash";
    let (refinement, search) = match provider {
        "openai" => (
            ModelConfig::openai(OPENAI_MODEL, openai_api_key)
                .reasoning_effort(ReasoningEffort::None)
                .verbosity(Verbosity::Low)
                .json_schema("decision_refinement_turn", refinement_config().model_turn_schema()),
            ProductSearch::new(
                OPENAI_MODEL,
                OpenAiCompatBackend::openai(openai_api_key)?
                    .reasoning_effort(ReasoningEffort::Low)
                    .verbosity(Verbosity::Low)
                    .output_format(OutputFormat::json_schema(
                        "product_search_results",
                        crate::aggregation::product_search_schema(),
                    ))
                    .web_search(WebSearchOptions {
                        required: true,
                        max_tool_calls: Some(6),
                        ..WebSearchOptions::default()
                    }),
            ),
        ),
        "gemini" => (
            ModelConfig::gemini(GEMINI_MODEL, gemini_api_key).json_mode(),
            // Gemini 2.5 search uses text output; the product prompt requests JSON, validated locally.
            ProductSearch::new(
                GEMINI_MODEL,
                GeminiBackend::google_ai(gemini_api_key)?
                    .output_format(OutputFormat::Text)
                    .web_search(),
            )
            .temperature(0.0),
        ),
        _ => return Err(format!("unsupported model provider {provider:?}; use openai or gemini")),
    };
    Ok((refinement.build()?.max_output_tokens(8192), search))
}

#[method::instance(export = http, method = "POST", path_prefix = "/api/scopes")]
fn http_start_scope(ctx: &mut _, request: http::Request) -> LyquidResult<http::Response> {
    let body = match decode_body::<StartScopeBody>(&request) {
        Ok(body) => body,
        Err(error) => return Ok(error_response(400, error)),
    };
    let user_request = body.request.trim().to_owned();
    if user_request.is_empty() {
        return Ok(error_response(400, "the shopping request must not be empty"));
    }
    let provider = ctx.instance.model_provider.read().clone();
    if provider.is_empty() {
        return Ok(error_response(
            400,
            "no model provider is configured; start the example with OPENAI_API_KEY or GEMINI_API_KEY",
        ));
    }
    let scope = (|| -> Result<Scope, String> {
        let (config, search) = model_setup(
            &provider,
            &ctx.instance.openai_api_key.read(),
            &ctx.instance.gemini_api_key.read(),
        )?;
        Ok(Scope::new(
            Arc::new(crate::flow::flow(move |context, round| search.search(context, round))),
            crate::flow::initial_state(ShoppingRequest::new(user_request.clone()))?,
            AutoCheckpointConfig::Disabled,
            Some(config),
        ))
    })();
    let scope = match scope {
        Ok(scope) => scope,
        Err(error) => return Ok(error_response(400, error)),
    };

    let scope_id = scope.execution_id().clone();
    {
        let mut active = ctx.instance.active_scope.write();
        // Whenever both registries are needed, lock Scopes before their display views.
        let mut scopes = ctx.instance.scopes.write();
        let mut views = ctx.instance.scope_views.write();
        if let Some((previous_id, handle)) = active.take() {
            handle.request_stop();
            scopes.remove(&previous_id);
            views.remove(&previous_id);
        }
        *active = Some((scope_id.clone(), scope.input_handle()));
        views.insert(scope_id.clone(), scope_view(&scope_id, scope.state()));
        scopes.insert(scope_id.clone(), scope);
    }
    trigger!(execute_scope(scope_id: String = scope_id.0.clone(), input: Option<String> = None), TriggerMode::Once(0));
    Ok(json_response(202, &StartedScope { scope_id, provider }))
}

#[method::instance(export = http, method = "GET", path_prefix = "/api/scope")]
fn http_scope(ctx: &_, request: http::Request) -> LyquidResult<http::Response> {
    let Some(scope_id) = query_scope_id(&request.url) else {
        return Ok(error_response(400, "missing or invalid Scope id"));
    };
    let views = ctx.instance.scope_views.read();
    let Some(view) = views.get(&scope_id) else {
        return Ok(error_response(404, "this search no longer exists; start a new search"));
    };
    Ok(json_response(200, view))
}

#[method::instance(export = http, method = "POST", path_prefix = "/api/refinements")]
fn http_refine(ctx: &mut _, request: http::Request) -> LyquidResult<http::Response> {
    let body = match decode_body::<RefineBody>(&request) {
        Ok(body) => body,
        Err(error) => return Ok(error_response(400, error)),
    };
    let message = body.message.trim().to_owned();
    if message.is_empty() {
        return Ok(error_response(400, "the refinement message must not be empty"));
    }
    let mut views = ctx.instance.scope_views.write();
    let Some(view) = views.get_mut(&body.scope_id) else {
        return Ok(error_response(404, "unknown shopping Scope"));
    };
    if !reserve_input(view, "refine") {
        return Ok(error_response(409, "the Scope is not waiting for refinement feedback"));
    }
    drop(views);
    trigger!(execute_scope(scope_id: String = body.scope_id.0, input: Option<String> = Some(message)), TriggerMode::Once(0));
    Ok(json_response(202, &serde_json::json!({ "accepted": true })))
}

#[method::instance(export = http, method = "POST", path_prefix = "/api/restarts")]
fn http_restart(ctx: &mut _, request: http::Request) -> LyquidResult<http::Response> {
    let body = match decode_body::<RestartBody>(&request) {
        Ok(body) => body,
        Err(error) => return Ok(error_response(400, error)),
    };
    let feedback = body.feedback.trim().to_owned();
    if feedback.is_empty() {
        return Ok(error_response(
            400,
            "restart feedback must describe why different candidates are needed",
        ));
    }
    let mut views = ctx.instance.scope_views.write();
    let Some(view) = views.get_mut(&body.scope_id) else {
        return Ok(error_response(404, "unknown shopping Scope"));
    };
    if !reserve_input(view, "restart") {
        return Ok(error_response(
            409,
            "the Scope is not waiting for new-candidate feedback",
        ));
    }
    drop(views);
    trigger!(execute_scope(scope_id: String = body.scope_id.0, input: Option<String> = Some(feedback)), TriggerMode::Once(0));
    Ok(json_response(202, &serde_json::json!({ "accepted": true })))
}

#[method::instance(export = http, method = "POST", path_prefix = "/api/choices")]
fn http_choose(ctx: &mut _, request: http::Request) -> LyquidResult<http::Response> {
    let body = match decode_body::<ChoiceBody>(&request) {
        Ok(body) => body,
        Err(error) => return Ok(error_response(400, error)),
    };
    if !refinement_config()
        .choice_options()
        .iter()
        .any(|choice| choice.id == body.choice)
    {
        return Ok(error_response(400, "unsupported shopping choice"));
    }
    let mut views = ctx.instance.scope_views.write();
    let Some(view) = views.get_mut(&body.scope_id) else {
        return Ok(error_response(404, "unknown shopping Scope"));
    };
    // Product links finish comparison outside the Flow; the web UI only offers Finish with no matches.
    let valid = view.choices.iter().any(|choice| choice.id == body.choice);
    if !valid || !reserve_input(view, "choice") {
        return Ok(error_response(409, "the Scope is not waiting for this choice"));
    }
    drop(views);
    trigger!(execute_scope(scope_id: String = body.scope_id.0, input: Option<String> = Some(body.choice)), TriggerMode::Once(0));
    Ok(json_response(202, &serde_json::json!({ "accepted": true })))
}

#[method::instance(export = http, method = "POST", path_prefix = "/api/revisions/switch")]
fn http_restore(ctx: &_, request: http::Request) -> LyquidResult<http::Response> {
    let body = match decode_body::<RestoreBody>(&request) {
        Ok(body) => body,
        Err(error) => return Ok(error_response(400, error)),
    };
    let mut scopes = ctx.instance.scopes.write();
    let mut views = ctx.instance.scope_views.write();
    let Some(view) = views.get_mut(&body.scope_id) else {
        return Ok(error_response(404, "unknown shopping Scope"));
    };
    let Some(scope) = scopes.get_mut(&body.scope_id) else {
        return Ok(error_response(
            409,
            "the Scope is processing; wait before restoring a checkpoint",
        ));
    };
    match restore_scope(scope, view, &body.revision_id) {
        Ok(()) => Ok(json_response(200, &serde_json::json!({ "restored": true }))),
        Err(error) => Ok(error_response(409, error)),
    }
}

#[method::instance]
fn execute_scope(ctx: &mut _, scope_id: String, input: Option<String>) -> LyquidResult<bool> {
    let scope_id = ScopeId(scope_id);
    let work = {
        let mut scopes = ctx.instance.scopes.write();
        let views = ctx.instance.scope_views.read();
        views
            .get(&scope_id)
            .filter(|view| view.status == "processing")
            .and_then(|view| scopes.remove(&scope_id).map(|scope| (scope, view.clone())))
    };
    if let Some((mut scope, mut view)) = work {
        // Scope owns execution and input validation. No registry lock is held during model calls.
        run_scope(&mut scope, &mut view, input);
        let mut scopes = ctx.instance.scopes.write();
        let mut views = ctx.instance.scope_views.write();
        publish_scope(&mut scopes, &mut views, scope, view);
    }
    Ok(true)
}

fn publish_scope(
    scopes: &mut HashMap<ScopeId, Scope>, views: &mut HashMap<ScopeId, ScopeView>, scope: Scope, view: ScopeView,
) {
    // A replaced search has been removed. Its in-flight result must not recreate it.
    if let Some(current) = views.get_mut(scope.execution_id()) {
        *current = view;
        scopes.insert(scope.execution_id().clone(), scope);
    }
}

/// Reserve the published input before scheduling its worker; there is no application input queue.
fn reserve_input(view: &mut ScopeView, kind: &str) -> bool {
    if view.status != "awaiting_input" || view.input_kind != Some(kind) {
        return false;
    }
    view.status = "processing";
    true
}

fn run_scope(scope: &mut Scope, view: &mut ScopeView, input: Option<String>) {
    let revision = input.as_ref().and_then(|message| match view.input_kind {
        Some("refine") => Some(("refinement", message.clone())),
        Some("restart") => Some(("search", message.clone())),
        _ => None,
    });
    let result = (|| {
        if let Some(value) = input {
            let field = match view.input_kind {
                Some("choice") => refinement_loop_flow::CHOICE_STATE_FIELD,
                Some("restart") => RESTART_FEEDBACK_FIELD,
                _ => refinement_loop_flow::REFINEMENT_INPUT_FIELD,
            };
            let handle = scope.input_handle();
            handle.submit_input(&serde_json::json!({field: value}).to_string())?;
        }
        scope.run_until_input()
    })();
    view.input_kind = None;
    view.choices.clear();
    view.error = None;
    match result {
        Ok(Some((spec, state))) => {
            let history = std::mem::take(&mut view.history);
            *view = scope_view(scope.execution_id(), &state);
            view.history = history;
            view.status = "awaiting_input";
            view.input_kind = Some(if spec.field_schema(refinement_loop_flow::CHOICE_STATE_FIELD).is_some() {
                "choice"
            } else if spec.field_schema(RESTART_FEEDBACK_FIELD).is_some() {
                "restart"
            } else {
                "refine"
            });
            if view.input_kind == Some("choice") {
                view.choices = shopping_choices(
                    state
                        .get::<DecisionState>(refinement_loop_flow::DECISION_STATE_FIELD)
                        .unwrap(),
                );
                if view.history.revisions.is_empty() || revision.is_some() {
                    let (kind, summary) = revision.unwrap_or_else(|| ("initial", view.request.clone()));
                    let id = scope.checkpoint();
                    view.history.revisions.push(RevisionView {
                        id: id.clone(),
                        parent_id: view.history.active_revision_id.clone(),
                        name: match kind {
                            "refinement" => format!("Refine: {summary}"),
                            "search" => format!("Search: {summary}"),
                            _ => "Original".to_owned(),
                        },
                        kind,
                        summary,
                        status: "awaiting_input",
                        active: true,
                        search_round: view.aggregation_round,
                        candidate_count: view.candidates.len(),
                        hard_constraints: view.hard_constraints.clone(),
                        soft_preferences: view.soft_preferences.clone(),
                    });
                    select_revision(&mut view.history, id);
                }
            }
        }
        Ok(None) if scope.current_step().0 == FINISHED_EXIT => {
            let history = std::mem::take(&mut view.history);
            *view = scope_view(scope.execution_id(), scope.state());
            view.history = history;
            view.status = "no_match";
        }
        result => {
            view.status = "failed";
            view.error = Some(match result {
                Err(error) => error.to_string(),
                _ => format!(
                    "shopping Scope completed through unexpected Step {}",
                    scope.current_step()
                ),
            });
        }
    }
}

fn restore_scope(scope: &mut Scope, view: &mut ScopeView, checkpoint: &ScopeId) -> Result<(), String> {
    if view.status == "processing" {
        return Err("the Scope is processing; wait before restoring a checkpoint".to_owned());
    }
    scope.restore(checkpoint).map_err(|error| error.to_string())?;
    // Checkpoints are saved at choice inputs. Re-read that input and its child State from Scope;
    // no saved application State or input contract is needed, and no model call is replayed.
    run_scope(scope, view, None);
    select_revision(&mut view.history, checkpoint.clone());
    Ok(())
}

fn select_revision(history: &mut HistoryView, id: ScopeId) {
    for revision in &mut history.revisions {
        revision.active = revision.id == id;
    }
    history.active_revision_id = Some(id);
}

fn scope_view(scope_id: &ScopeId, state: &State) -> ScopeView {
    let catalog = state
        .get::<ProductCatalog>(crate::flow::CATALOG_STATE_FIELD)
        .cloned()
        .unwrap_or_default();
    let decision = state
        .get::<DecisionState>(refinement_loop_flow::DECISION_STATE_FIELD)
        .cloned()
        .unwrap_or_default();
    let search_state = state
        .get::<ShoppingSearchState>(crate::flow::SHOPPING_SEARCH_STATE_FIELD)
        .cloned()
        .unwrap_or_default();
    let candidates = decision
        .ranking
        .candidate_ids
        .iter()
        .filter_map(|id| catalog.products.iter().find(|product| product.id == id.0))
        .cloned()
        .collect();
    ScopeView {
        scope_id: scope_id.clone(),
        status: "processing",
        input_kind: None,
        request: state
            .get::<ShoppingRequest>(SHOPPING_REQUEST_STATE_FIELD)
            .unwrap()
            .user_request
            .clone(),
        search_summary: catalog.search_summary,
        retrieved_sources: catalog.retrieved_sources,
        choices: vec![],
        hint: decision.question.prompt,
        hard_constraints: decision.goal.hard_constraints,
        soft_preferences: decision.goal.soft_preferences,
        aggregation_round: search_state.aggregation_round,
        restart_feedback: search_state.restart_feedback,
        candidates,
        history: HistoryView::default(),
        error: None,
    }
}

fn decode_body<T: for<'de> Deserialize<'de>>(request: &http::Request) -> Result<T, String> {
    let body = request
        .body
        .as_deref()
        .ok_or_else(|| "missing JSON request body".to_owned())?;
    serde_json::from_slice(body).map_err(|error| format!("invalid JSON request body: {error}"))
}

fn query_scope_id(url: &str) -> Option<ScopeId> {
    url.split_once('?')?.1.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(key, value)| *key == "id" && !value.is_empty())
            .map(|(_, value)| ScopeId(value.to_owned()))
    })
}

fn json_response<T: Serialize>(status: u16, value: &T) -> http::Response {
    http::Response {
        status,
        headers: vec![http::Header {
            name: "content-type".into(),
            value: b"application/json".to_vec(),
        }],
        body: serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"failed to serialize response\"}".to_vec()),
    }
}

fn error_response(status: u16, message: impl Into<String>) -> http::Response {
    json_response(status, &ErrorBody { error: message.into() })
}
