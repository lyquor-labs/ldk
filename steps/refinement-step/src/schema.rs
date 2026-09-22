//! Provider-neutral JSON response contract for model-driven refinement turns.

/// Returns the complete structured turn expected by a refinement Step.
///
/// Applications may supply this schema to a provider's structured-output API.
/// Provider-specific options, authentication, and model selection stay with the caller.
/// Finalization still validates the response when a backend does not enforce the schema.
pub fn model_turn_schema(next: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "type": { "type": "string", "enum": ["advance"] },
            "next": { "type": "string", "enum": [next] },
            "updates": {
                "type": "object",
                "properties": {
                    crate::DECISION_STATE_FIELD: {
                        "type": "object",
                        "properties": {
                            "goal": {
                                "type": "object",
                                "properties": {
                                    "hard_constraints": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    },
                                    "soft_preferences": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    }
                                },
                                "required": ["hard_constraints", "soft_preferences"],
                                "additionalProperties": false
                            },
                            "ranking": {
                                "type": "object",
                                "properties": {
                                    "candidate_ids": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    }
                                },
                                "required": ["candidate_ids"],
                                "additionalProperties": false
                            },
                            "question": {
                                "type": "object",
                                "properties": {
                                    "prompt": { "type": "string" }
                                },
                                "required": ["prompt"],
                                "additionalProperties": false
                            }
                        },
                        "required": ["goal", "ranking", "question"],
                        "additionalProperties": false
                    }
                },
                "required": [crate::DECISION_STATE_FIELD],
                "additionalProperties": false
            }
        },
        "required": ["type", "next", "updates"],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use lyquid_test::test;
    use serde_json::json;

    use super::*;
    use crate::{DECISION_STATE_FIELD, DecisionState};

    #[test]
    fn model_contract_requires_only_a_complete_decision_update() {
        let schema = model_turn_schema("show_results");
        let properties = &schema["properties"];
        assert_eq!(properties["type"]["enum"], json!(["advance"]));
        assert_eq!(properties["next"]["enum"], json!(["show_results"]));
        assert_eq!(schema["required"], json!(["type", "next", "updates"]));
        let updates = &properties["updates"];
        assert_eq!(updates["required"], json!([DECISION_STATE_FIELD]));
        assert_eq!(updates["properties"].as_object().unwrap().len(), 1);
        assert_eq!(updates["additionalProperties"], false);

        let decision_schema = &updates["properties"][DECISION_STATE_FIELD];
        let decision = serde_json::to_value(DecisionState::default()).unwrap();
        for (field, value) in decision.as_object().unwrap() {
            assert!(decision_schema["required"].as_array().unwrap().contains(&json!(field)));
            let field_schema = &decision_schema["properties"][field];
            assert_eq!(field_schema["additionalProperties"], false);
            assert_eq!(
                field_schema["properties"].as_object().unwrap().len(),
                value.as_object().unwrap().len()
            );
            for key in value.as_object().unwrap().keys() {
                assert!(field_schema["required"].as_array().unwrap().contains(&json!(key)));
            }
        }
    }
}
