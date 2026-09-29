#![doc(html_no_source)]

//! Shopping-assistant Flow using web search followed by fixed-list refinement.

#[path = "aggregation-step.rs"] mod aggregation;
mod flow;
mod types;

pub use aggregation::{Product, ProductCatalog, ProductSearch, SearchContext};
pub use flow::{
    AGGREGATE_CANDIDATES_STEP, CATALOG_STATE_FIELD, FINISH_CHOICE, FINISHED_EXIT, REFINE_CANDIDATES_STEP,
    RESTART_CHOICE, RESTART_FEEDBACK_FIELD, RESTART_FEEDBACK_STEP, SHOPPING_REQUEST_STATE_FIELD,
    SHOPPING_SEARCH_STATE_FIELD, catalog, flow, initial_state, refinement_config,
};
pub use types::{ShoppingRequest, ShoppingSearchState};

// `state!` must expand at the crate root, so the hosted service is included here.
include!("service.rs");

#[cfg(test)]
mod service_tests {
    use super::*;
    use lyquid_test::test;

    #[test]
    fn web_choices_come_from_the_loop_and_only_offer_finish_for_empty_rankings() {
        let mut decision = DecisionState::default();
        let choices = shopping_choices(&decision);
        assert_eq!(
            choices.iter().map(|choice| choice.id.as_str()).collect::<Vec<_>>(),
            [refinement_loop_flow::CONTINUE_CHOICE, RESTART_CHOICE, FINISH_CHOICE]
        );
        decision.ranking.candidate_ids.push("asin".into());
        assert_eq!(
            shopping_choices(&decision)
                .iter()
                .map(|choice| choice.id.as_str())
                .collect::<Vec<_>>(),
            [refinement_loop_flow::CONTINUE_CHOICE, RESTART_CHOICE]
        );
    }

    #[test]
    fn product_links_and_display_facts_come_from_the_canonical_catalog() {
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
}
