#![doc(html_no_source)]

//! Shopping-assistant Flow using web search followed by fixed-list refinement.

#[path = "aggregation-step.rs"] mod aggregation;
mod flow;

pub use aggregation::{Product, ProductCatalog, ProductSearch, SearchContext};
pub use flow::{
    AGGREGATE_CANDIDATES_STEP, CATALOG_STATE_FIELD, FINISH_CHOICE, FINISHED_EXIT, REFINE_CANDIDATES_STEP,
    RESTART_CHOICE, RESTART_FEEDBACK_FIELD, RESTART_FEEDBACK_STEP, SHOPPING_REQUEST_STATE_FIELD, SHOPPING_REQUEST_STEP,
    SHOPPING_SEARCH_STATE_FIELD, catalog, flow, initial_state, refinement_config,
};

use std::sync::Arc;

use lyquid::prelude::*;
use lyquid_flow::{AutoCheckpointConfig, Scope, Value};
use lyquid_llm::{
    ModelConfig, OutputFormat, Usage, UsageTotals, UsageTracker,
    backend::{
        gemini::GeminiBackend,
        openai_compat::{OpenAiCompatBackend, ReasoningEffort, Verbosity, WebSearchOptions},
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Parent-owned state carried across candidate aggregation rounds.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShoppingSearchState {
    pub aggregation_round: u64,
    pub restart_feedback: Vec<String>,
}

impl Value for ShoppingSearchState {
    fn encode(&self) -> String {
        serde_json::to_string(self).expect("ShoppingSearchState serialization cannot fail")
    }

    fn decode(&self, model_output: &str) -> Result<Box<dyn Value>, String> {
        serde_json::from_str::<Self>(model_output)
            .map(|value| Box::new(value) as Box<dyn Value>)
            .map_err(|error| error.to_string())
    }

    fn clone_box(&self) -> Box<dyn Value> {
        Box::new(self.clone())
    }
}

lyquid_flow::serve_flow! {
    state {
        instance settings: Settings = Settings::default();
    }
    replace_existing: true;
    create(ctx) {
        create_scope(&ctx.instance.settings.read())
    }
}

#[derive(Default)]
struct Settings {
    provider: String,
    api_key: String,
}

#[method::instance(export = eth)]
fn set_model_api_key(ctx: &mut _, provider: String, api_key: String) -> LyquidResult<bool> {
    let provider = provider.trim().to_ascii_lowercase();
    let api_key = api_key.trim().to_owned();
    if api_key.is_empty() {
        return Err(LyquidError::LyquorRuntime("the model API key must not be empty".into()));
    }
    if !matches!(provider.as_str(), "openai" | "gemini") {
        return Err(LyquidError::LyquorRuntime(format!(
            "unsupported model provider {provider:?}; use openai or gemini"
        )));
    }
    *ctx.instance.settings.write() = Settings { provider, api_key };
    Ok(true)
}

fn create_scope(settings: &Settings) -> Result<Scope, String> {
    if settings.provider.is_empty() {
        return Err("no model provider is configured; start the example with OPENAI_API_KEY or GEMINI_API_KEY".into());
    }
    let usage = UsageTracker::<SessionUsage>::default();
    let (config, search) = model_setup(
        &settings.provider,
        &settings.api_key,
        usage_observer(usage.clone(), UsagePhase::Search),
    )?;
    let observe_refinement = usage_observer(usage, UsagePhase::Refinement);
    Ok(Scope::new(
        Arc::new(crate::flow::flow(move |context, round| search.search(context, round))),
        crate::flow::initial_state()?,
        AutoCheckpointConfig::Disabled,
        Some(config),
    )
    .on_usage(move |_, usage| observe_refinement(usage)))
}

fn model_setup(
    provider: &str, api_key: &str, observe_search: impl Fn(Option<&Usage>) + Send + Sync + 'static,
) -> Result<(ModelConfig, ProductSearch), String> {
    const OPENAI_MODEL: &str = "gpt-5.4";
    const GEMINI_MODEL: &str = "gemini-2.5-flash";
    let (refinement, search) = match provider {
        "openai" => (
            ModelConfig::openai(OPENAI_MODEL, api_key)
                .reasoning_effort(ReasoningEffort::None)
                .verbosity(Verbosity::Low)
                .json_schema("decision_refinement_turn", refinement_config().model_turn_schema()),
            ProductSearch::new(
                OPENAI_MODEL,
                lyquid_llm::with_usage_observer(
                    OpenAiCompatBackend::openai(api_key)?
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
                    observe_search,
                ),
            ),
        ),
        "gemini" => (
            ModelConfig::gemini(GEMINI_MODEL, api_key).json_mode(),
            // Gemini 2.5 search uses text output; the product prompt requests JSON, validated locally.
            ProductSearch::new(
                GEMINI_MODEL,
                lyquid_llm::with_usage_observer(
                    GeminiBackend::google_ai(api_key)?
                        .output_format(OutputFormat::Text)
                        .web_search(),
                    observe_search,
                ),
            )
            .temperature(0.0),
        ),
        _ => return Err(format!("unsupported model provider {provider:?}; use openai or gemini")),
    };
    Ok((refinement.build()?.max_output_tokens(8192), search))
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum UsagePhase {
    Search,
    Refinement,
}

/// Session accounting kept outside Flow state and history checkpoints.
#[derive(Clone, Default)]
struct SessionUsage {
    search: UsageTotals,
    refinement: UsageTotals,
}

impl SessionUsage {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "search": self.search,
            "refinement": self.refinement,
            "total": self.search.combined(&self.refinement),
        })
    }
}

fn usage_observer(tracker: UsageTracker<SessionUsage>, phase: UsagePhase) -> impl Fn(Option<&Usage>) + Send + Sync {
    move |usage| {
        let session = tracker.record(|session| match phase {
            UsagePhase::Search => session.search.record(usage),
            UsagePhase::Refinement => session.refinement.record(usage),
        });
        let mut event = session.to_json();
        event["phase"] = json!(phase);
        event["usage"] = json!(usage);
        lyquid::println!("shopping_token_usage {event}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lyquid_test::test;

    #[test]
    fn catalog_display_fields() {
        let product = Product {
            id: "product-1-1".into(),
            title: "TV from search".into(),
            source_url: "https://maker.example/tv".into(),
            source: "Maker".into(),
            price: None,
            summary: "Gaming TV".into(),
            attributes: vec!["120 Hz".into()],
        };
        let value = serde_json::to_value(&product).unwrap();
        assert_eq!(value["source_url"], product.source_url);
        assert_eq!(value["title"], product.title);
        assert!(value["price"].is_null());
    }

    #[test]
    fn usage_observers() {
        let tracker = UsageTracker::<SessionUsage>::default();
        let search = usage_observer(tracker.clone(), UsagePhase::Search);
        let refinement = usage_observer(tracker.clone(), UsagePhase::Refinement);
        search(Some(&Usage {
            input_tokens: Some(20),
            output_tokens: Some(10),
            total_tokens: Some(35),
        }));
        refinement(Some(&Usage {
            input_tokens: Some(5),
            output_tokens: Some(3),
            total_tokens: Some(9),
        }));
        assert_eq!(
            tracker.snapshot().to_json(),
            json!({
                "search": {"call_attempts": 1, "input_tokens": 20, "output_tokens": 10, "total_tokens": 35},
                "refinement": {"call_attempts": 1, "input_tokens": 5, "output_tokens": 3, "total_tokens": 9},
                "total": {"call_attempts": 2, "input_tokens": 25, "output_tokens": 13, "total_tokens": 44},
            })
        );
    }
}
