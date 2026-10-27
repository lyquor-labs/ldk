//! Shopping result and history declarations consumed by the shared Flow page.

use lyquid_flow::{FlowError, Scope, ViewSpec};
use refinement_loop_flow::{DECISION_STATE_FIELD, DecisionState, REFINEMENT_INPUT_FIELD};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::{
    CATALOG_STATE_FIELD, Product, ProductCatalog, SHOPPING_REQUEST_STATE_FIELD, SHOPPING_SEARCH_STATE_FIELD,
    ShoppingSearchState,
};

#[derive(Deserialize, Serialize)]
pub(super) struct ShoppingResult {
    pub request: String,
    pub hint: String,
    pub hard_constraints: Vec<String>,
    pub soft_preferences: Vec<String>,
    pub aggregation_round: u64,
    pub restart_feedback: Vec<String>,
    pub feedback: String,
    pub search_summary: String,
    pub retrieved_sources: Vec<String>,
    pub candidates: Vec<Product>,
}

fn shopping_result(scope: &Scope) -> ShoppingResult {
    let state = scope.state();
    let catalog = state
        .get(CATALOG_STATE_FIELD)
        .and_then(|value| serde_json::from_value::<ProductCatalog>(value.clone()).ok())
        .expect("shopping catalog");
    let decision = state
        .get(DECISION_STATE_FIELD)
        .and_then(|value| serde_json::from_value::<DecisionState>(value.clone()).ok())
        .expect("shopping decision");
    let search = state
        .get(SHOPPING_SEARCH_STATE_FIELD)
        .and_then(|value| serde_json::from_value::<ShoppingSearchState>(value.clone()).ok())
        .expect("shopping search");
    ShoppingResult {
        request: state
            .get(SHOPPING_REQUEST_STATE_FIELD)
            .and_then(serde_json::Value::as_str)
            .expect("shopping request")
            .to_owned(),
        hint: decision.question.prompt,
        hard_constraints: decision.goal.hard_constraints,
        soft_preferences: decision.goal.soft_preferences,
        aggregation_round: search.aggregation_round,
        restart_feedback: search.restart_feedback,
        feedback: state
            .get(REFINEMENT_INPUT_FIELD)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_default(),
        search_summary: catalog.search_summary,
        retrieved_sources: catalog.retrieved_sources,
        candidates: decision
            .ranking
            .candidate_ids
            .iter()
            .filter_map(|id| catalog.products.iter().find(|product| product.id == id.0))
            .cloned()
            .collect(),
    }
}

pub(super) fn shopping_view(scope: &Scope) -> Result<ViewSpec, FlowError> {
    let result = shopping_result(scope);
    if result.aggregation_round == 0 {
        return Ok(ViewSpec::default());
    }
    let ui = ViewSpec::builder();
    let mut content = vec![ui.heading(&result.request), ui.text(&result.search_summary)];
    for (label, values) in [
        ("Requirements", &result.hard_constraints),
        ("Preferences", &result.soft_preferences),
    ] {
        if !values.is_empty() {
            content.push(ui.heading(label));
            content.push(ui.text(values.join(" · ")));
        }
    }
    let mut products = Vec::new();
    for product in &result.candidates {
        products.push(ui.card(ui.column(vec![
            ui.heading(&product.title),
            ui.text(product.price.as_deref().unwrap_or("Price not verified")),
            ui.text(&product.summary),
            ui.link("View product ↗", &product.source_url),
        ])));
    }
    content.push(ui.row(products));
    content.push(ui.text(&result.hint));
    ui.data("shopping", &result);
    ViewSpec::finish(&ui, ui.column(content)).map_err(FlowError::from)
}

/// Save recommendation pages; intermediate text prompts do not become history nodes.
pub(super) fn shopping_history(scope: &Scope, previous: Option<&JsonValue>) -> Result<Option<JsonValue>, FlowError> {
    if !scope
        .input_handle()
        .input_spec()
        .is_some_and(|spec| spec.field_schema(refinement_loop_flow::CHOICE_STATE_FIELD).is_some())
    {
        return Ok(None);
    }
    let result = shopping_result(scope);
    let (kind, summary) = match previous {
        None => ("initial", result.request),
        Some(previous) if previous["search_round"].as_u64() != Some(result.aggregation_round) => {
            ("search", result.restart_feedback.last().cloned().unwrap_or_default())
        }
        Some(_) => ("refinement", result.feedback),
    };
    let name = match kind {
        "refinement" => format!("Refine: {summary}"),
        "search" => format!("Search: {summary}"),
        _ => "Original".into(),
    };
    Ok(Some(json!({
        "name": name, "kind": kind, "summary": summary,
        "search_round": result.aggregation_round,
        "candidate_count": result.candidates.len(),
        "hard_constraints": result.hard_constraints,
        "soft_preferences": result.soft_preferences,
    })))
}
