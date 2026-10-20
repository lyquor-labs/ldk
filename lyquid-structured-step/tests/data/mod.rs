use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use lyquid_flow::{
    AutoCheckpointConfig, Flow, FlowError, InputSpec, ModelTemplate, Scope, State, StateUpdates, Step, TemplateSpec,
    TurnProposal,
};
use lyquid_llm::{
    Backend, JsonApiResponse, LlmError, LlmResult, ModelConfig, ModelRequest, ModelResponse, PreparedJsonApiRequest,
};
use lyquid_test::test;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{BindingTarget, Presence, StepConfiguration, StructuredStepBuilder, ValueSource};

mod static_input;

fn scope(step: impl Step, state: State) -> Scope {
    Scope::new(
        Arc::new(
            Flow::builder("contracts")
                .entry("start")
                .exit("done")
                .step("start", step)
                .build()
                .unwrap(),
        ),
        state,
        AutoCheckpointConfig::Disabled,
        None,
    )
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Count {
    count: u64,
}

#[test]
fn nested_projection_retains_native_u64_and_reusable_bindings() {
    let builder = StructuredStepBuilder::operation_with_config("identity", (), |value: &Count, &()| Ok(value.count))
        .data::<u64>("count")
        .result::<u64>()
        .next("done");
    assert!(builder.to_json().is_ok());
    assert!(builder.clone().build().err().unwrap().contains("no binding"));
    for name in ["first", "second"] {
        let bound = builder
            .clone()
            .bind_data("count", ValueSource::State { field: name.into() }.at("/items/0/count"))
            .update("output", "");
        let encoded = bound.to_json().unwrap();
        let built = bound.build().unwrap();
        assert_eq!(encoded, built.to_json().unwrap());
        let mut run = scope(
            built,
            State::builder()
                .field(name, "Nested source", json!({"items": [{"count": u64::MAX}]}))
                .field("output", "Typed output", 0_u64)
                .build()
                .unwrap(),
        );
        run.advance().unwrap();
        assert_eq!(run.state().get::<u64>("output"), Some(&u64::MAX));
    }
}

#[test]
fn required_optional_default_and_null_have_distinct_meanings() {
    let step = StructuredStepBuilder::new()
        .data::<Option<String>>("nullable")
        .optional_data::<String>("absent")
        .data_default::<Option<String>>("defaulted", None)
        .bind_data("nullable", ValueSource::Constant { value: Value::Null })
        .update("output", "")
        .next("done");
    let saved = step.to_json().unwrap();
    let restored: StepConfiguration = serde_json::from_str(&saved).unwrap();
    assert!(matches!(
        &restored.data.arguments["defaulted"].presence,
        Presence::Default { value: Value::Null }
    ));
    let mut run = scope(
        step.build().unwrap(),
        State::builder().field("output", "Output", json!({})).build().unwrap(),
    );
    run.advance().unwrap();
    assert_eq!(
        run.state().get::<Value>("output"),
        Some(&json!({"nullable": null, "defaulted": null}))
    );
    assert!(
        StructuredStepBuilder::new()
            .data::<String>("value")
            .bind_data("value", ValueSource::Constant { value: Value::Null })
            .build()
            .is_err()
    );
}

#[test]
fn declarations_reject_invalid_defaults_duplicates_and_known_bad_results() {
    assert!(
        StructuredStepBuilder::new()
            .data::<String>("value")
            .data::<String>("value")
            .to_json()
            .is_err()
    );
    assert!(
        StructuredStepBuilder::new()
            .data_schema(
                "value",
                json!({"type": "integer"}),
                Presence::Default { value: json!("text") }
            )
            .build()
            .is_err()
    );
    assert!(
        StructuredStepBuilder::new()
            .data::<u64>("value")
            .bind_state("other", "source")
            .build()
            .is_err()
    );
    for source in [
        ValueSource::Result {
            pointer: "/missing".into(),
        },
        ValueSource::Result { pointer: "".into() }.at("/missing"),
        ValueSource::Result {
            pointer: "/missing".into(),
        }
        .at(""),
        ValueSource::Result {
            pointer: "/count".into(),
        }
        .at("/missing"),
        ValueSource::Result { pointer: "".into() }.at("/count").at("/missing"),
    ] {
        let builder = StructuredStepBuilder::new()
            .result::<Count>()
            .bind(source, BindingTarget::State { field: "output".into() });
        for error in [builder.to_json().unwrap_err(), builder.build().err().unwrap()] {
            assert!(error.contains("result"), "{error}");
            assert!(error.contains("/missing"), "{error}");
        }
    }
    let step = StructuredStepBuilder::new()
        .data::<u8>("value")
        .bind_data("value", ValueSource::Constant { value: json!(256) });
    assert!(step.build().is_err());
}

#[test]
fn result_projections_resolve_terminal_schema_references() {
    struct ReferencedResult<const ALLOWED: bool>;

    impl<const ALLOWED: bool> JsonSchema for ReferencedResult<ALLOWED> {
        fn schema_name() -> std::borrow::Cow<'static, str> {
            format!("ReferencedResult_{ALLOWED}").into()
        }

        fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
            json!({
                "type": "object",
                "properties": {
                    "x": {"$ref": "#/$defs/value"},
                    "chained": {"$ref": "#/$defs/alias"},
                    "items": {"type": "array", "items": {"$ref": "#/$defs/alias"}}
                },
                "$defs": {"value": ALLOWED, "alias": {"$ref": "#/$defs/value"}}
            })
            .try_into()
            .unwrap()
        }
    }

    for pointer in ["/x", "/chained", "/items/0"] {
        let forbidden = StructuredStepBuilder::new()
            .result::<ReferencedResult<false>>()
            .update("output", pointer);
        for error in [forbidden.to_json().unwrap_err(), forbidden.build().err().unwrap()] {
            assert!(error.contains("result schema forbids the value"), "{error}");
            assert!(error.contains(pointer), "{error}");
        }
        let allowed = StructuredStepBuilder::new()
            .result::<ReferencedResult<true>>()
            .update("output", pointer);
        assert!(allowed.to_json().is_ok());
        assert!(allowed.build().is_ok());
    }
}

#[test]
fn result_selectors_preserve_valid_paths_and_runtime_array_checks() {
    for (source, succeeds) in [
        (ValueSource::Result { pointer: "/0".into() }.at("/count"), true),
        (ValueSource::Result { pointer: "".into() }.at("/0").at("/count"), true),
        (ValueSource::Result { pointer: "/1".into() }.at("/count"), false),
    ] {
        let builder = StructuredStepBuilder::new()
            .action_with_config("counts", (), |_, _, &()| Ok(vec![Count { count: 7 }]))
            .result::<Vec<Count>>()
            .bind(source, BindingTarget::State { field: "output".into() })
            .next("done");
        assert!(builder.to_json().is_ok());
        let mut run = scope(
            builder.build().unwrap(),
            State::builder().field("output", "Output", 42_u64).build().unwrap(),
        );
        let result = run.advance();
        if succeeds {
            result.unwrap();
            assert_eq!(run.state().get::<u64>("output"), Some(&7));
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("/1"), "{error}");
            assert_eq!(run.state().get::<u64>("output"), Some(&42));
            assert!(run.trace().entries.is_empty());
        }
    }
}

#[test]
fn result_routes_reject_known_impossible_paths_and_non_string_types() {
    let base = StructuredStepBuilder::new().action_with_config("unused", (), |_, _, &()| -> Result<Value, String> {
        panic!("construction must not run actions")
    });
    for (builder, pointer) in [
        (base.clone().result::<u64>(), ""),
        (base.clone().result::<Count>(), "/missing"),
        (base.clone().result::<Count>(), "/count"),
        (base.clone().result::<Count>(), "/count/child"),
        (base.clone().result::<Vec<Count>>(), "/0"),
        (base.result::<(String,)>(), "/1"),
    ] {
        let builder = builder.route_by(pointer, [("done", "done")]);
        for error in [builder.to_json().unwrap_err(), builder.build().err().unwrap()] {
            assert!(error.contains("result route"), "{error}");
            assert!(error.contains(pointer), "{error}");
        }
    }
}

#[test]
fn result_routes_allow_strings_and_defer_value_dependent_failures() {
    for (builder, pointer, output, succeeds) in [
        (StructuredStepBuilder::new().result::<String>(), "", json!("done"), true),
        (
            StructuredStepBuilder::new().result::<Option<String>>(),
            "",
            json!("done"),
            true,
        ),
        (
            StructuredStepBuilder::new().result::<Option<String>>(),
            "",
            Value::Null,
            false,
        ),
        (StructuredStepBuilder::new().result::<Value>(), "", json!(7), false),
        (
            StructuredStepBuilder::new().result::<Vec<String>>(),
            "/0",
            json!(["done"]),
            true,
        ),
        (
            StructuredStepBuilder::new().result::<Vec<String>>(),
            "/0",
            json!([]),
            false,
        ),
    ] {
        let builder = builder
            .action_with_config("route", output, |_, _, output| Ok(output.clone()))
            .constant("output", 9_u64)
            .route_by(pointer, [("done", "done")]);
        let saved = builder.to_json().unwrap();
        let step = builder.build().unwrap();
        assert_eq!(step.to_json().unwrap(), saved);
        let mut run = scope(
            step,
            State::builder().field("output", "Output", 42_u64).build().unwrap(),
        );
        let result = run.advance();
        if succeeds {
            result.unwrap();
            assert!(run.is_finished());
            assert_eq!(run.state().get::<u64>("output"), Some(&9));
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("string route"), "{error}");
            assert_eq!(run.state().get::<u64>("output"), Some(&42));
            assert_eq!(run.current_step().0, "start");
            assert!(run.trace().entries.is_empty());
        }
    }
}

#[test]
fn input_and_output_schemas_follow_serde_direction() {
    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct Renamed {
        #[serde(rename(serialize = "sent", deserialize = "received"))]
        field: String,
    }
    let step = StructuredStepBuilder::new()
        .data::<Renamed>("payload")
        .result::<Renamed>();
    let contract = step.data_contract();
    assert!(
        contract.arguments["payload"].schema["properties"]
            .get("received")
            .is_some()
    );
    assert!(contract.result.as_ref().unwrap()["properties"].get("sent").is_some());
    let saved: Value = serde_json::from_str(&step.to_json().unwrap()).unwrap();
    assert!(saved["data"]["arguments"]["payload"]["schema"].is_object());
}

#[test]
fn input_presentation_receives_bound_data_before_interactive_input() {
    let step = StructuredStepBuilder::new()
        .data::<String>("prompt")
        .data::<String>("answer")
        .bind_state("prompt", "question")
        .bind_input("answer", "reply")
        .with_data_input_factory_config("ask", (), |data, &()| {
            assert!(data.get("answer").is_none());
            let mut input = InputSpec::builder();
            let field = input
                .field("reply", data["prompt"].as_str().unwrap(), String::new())
                .text_input();
            input.finish(field).map_err(Into::into)
        })
        .action_with_config("render", (), |context, _, &()| {
            context.render("{{ context.prompt }}: {{ context.answer }}")
        })
        .result::<String>()
        .update("output", "")
        .next("done");
    let mut run = scope(
        step.build().unwrap(),
        State::builder()
            .field("question", "Prompt", "Which candidate?".to_owned())
            .field("output", "Output", String::new())
            .build()
            .unwrap(),
    );
    let (input, _) = run.run_until_input().unwrap().unwrap();
    assert_eq!(input.field_schema("reply").unwrap()["title"], "Which candidate?");
    run.input_handle().submit_input(r#"{"reply":"{{ literal }}"}"#).unwrap();
    run.run_until_input().unwrap();
    assert_eq!(
        run.state().get::<String>("output").unwrap(),
        "Which candidate?: {{ literal }}"
    );
}

struct CapturePrompt(Arc<Mutex<Vec<String>>>);

impl Backend for CapturePrompt {
    fn prepare_request(&self, request: &ModelRequest) -> LlmResult<PreparedJsonApiRequest> {
        self.0.lock().unwrap().push(request.prompt.clone());
        Err(LlmError::Backend {
            provider: "fixture".into(),
            message: "captured without sending HTTP".into(),
        })
    }

    fn parse_response(&self, _: JsonApiResponse) -> LlmResult<ModelResponse> {
        unreachable!("the fixture never sends HTTP")
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct PromptRequest {
    label: String,
    items: Vec<Count>,
}

#[test]
fn native_model_prompt_uses_bound_data_and_input_in_every_section_once() {
    let mut input = InputSpec::builder();
    let reply = input.field("reply", "Reply", String::new()).text_input();
    let base = StructuredStepBuilder::new()
        .data::<PromptRequest>("request")
        .data::<String>("answer")
        .bind_input("answer", "reply")
        .with_input(input.finish(reply).unwrap())
        .with_model(ModelTemplate::new(
            "{{ context.request.label }}={{ context.request.items[0].count }}; answer={{ context.answer }}",
            vec![(Some("done".into()), "Continue for {{ context.request.label }}".into())],
            vec![("output".into(), "Use {{ context.answer }}".into())],
        ))
        .next("done");
    let saved: StepConfiguration = serde_json::from_str(&base.to_json().unwrap()).unwrap();
    assert!(saved.model.unwrap().goal.contains("context.request.items[0].count"));
    for field in ["first_source", "another_source"] {
        let step = base
            .clone()
            .bind_data("request", ValueSource::State { field: field.into() }.at("/payload"))
            .action_with_config("unreachable", (), |_, _, &()| -> Result<(), String> {
                panic!("the backend rejects the request before finalization")
            })
            .build()
            .unwrap();
        let prompts = Arc::new(Mutex::new(vec![]));
        let flow = Flow::builder("prompts")
            .entry("start")
            .exit("done")
            .step("start", step)
            .build()
            .unwrap();
        let state = State::builder()
            .field(
                field,
                "Request",
                json!({"payload": {"label": "{{ state.output }}", "items": [{"count": 7}]}}),
            )
            .field("output", "Output", "unchanged".to_owned())
            .build()
            .unwrap();
        let mut run = Scope::new(
            Arc::new(flow),
            state,
            AutoCheckpointConfig::Disabled,
            Some(ModelConfig::new("fixture", CapturePrompt(prompts.clone()))),
        );
        run.run_until_input().unwrap().unwrap();
        assert!(prompts.lock().unwrap().is_empty());
        assert!(run.input_handle().submit_input(r#"{"reply":1}"#).is_err());
        assert!(prompts.lock().unwrap().is_empty());
        run.input_handle().submit_input(r#"{"reply":"{{ missing }}"}"#).unwrap();
        assert!(matches!(run.run_until_input(), Err(FlowError::Model(_))));
        let captured = prompts.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].contains("{{ state.output }}=7; answer={{ missing }}"));
        assert!(captured[0].contains("- `done`: Continue for {{ state.output }}"));
        assert!(captured[0].contains("- `output`: Use {{ missing }}"));
        assert_eq!(run.state().get::<String>("output").unwrap(), "unchanged");
        assert_eq!(run.current_step().0, "start");
        assert!(run.trace().entries.is_empty());
    }
}

#[test]
fn model_context_exposes_prepared_values_and_rejects_invalid_arguments_before_backend() {
    let step = StructuredStepBuilder::operation(|context: &Count| Ok(context.count))
        .data::<u64>("count")
        .bind_state("count", "source")
        .with_context(|count: Count| Ok(Count { count: count.count + 1 }))
        .with_model(ModelTemplate::new(
            "{{ context.count }}",
            vec![(Some("done".into()), "Done".into())],
            vec![],
        ))
        .next("done");
    for value in [json!(7), json!("invalid")] {
        let bound = step.clone().build().unwrap();
        let prompts = Arc::new(Mutex::new(vec![]));
        let flow = Flow::builder("prepared")
            .entry("start")
            .exit("done")
            .step("start", bound)
            .build()
            .unwrap();
        let state = State::builder()
            .field("source", "Count", value.clone())
            .build()
            .unwrap();
        let mut run = Scope::new(
            Arc::new(flow),
            state,
            AutoCheckpointConfig::Disabled,
            Some(ModelConfig::new("fixture", CapturePrompt(prompts.clone()))),
        );
        let error = run.advance().unwrap_err();
        let captured = prompts.lock().unwrap();
        if value.is_number() {
            assert!(matches!(error, FlowError::Model(_)));
            assert_eq!(captured.len(), 1);
            assert!(captured[0].starts_with("# Step goal\n8\n"));
        } else {
            assert!(error.to_string().contains("argument count"));
            assert!(captured.is_empty());
        }
        assert_eq!(run.state().get::<Value>("source"), Some(&value));
        assert!(run.trace().entries.is_empty());
    }
}

#[test]
fn invalid_arguments_prevent_actions_and_result_failure_prevents_commit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let base = StructuredStepBuilder::new()
        .data::<u64>("count")
        .bind_state("count", "source")
        .action_with_config("bad-result", (), move |_, _, &()| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(json!("not a number"))
        })
        .result::<u64>()
        .update("output", "")
        .next("done");
    for (value, expected) in [(json!("wrong"), 0), (json!(1), 1)] {
        let mut run = scope(
            base.clone().build().unwrap(),
            State::builder()
                .field("source", "Input", value)
                .field("output", "Output", 42_u64)
                .build()
                .unwrap(),
        );
        assert!(run.advance().is_err());
        assert_eq!(calls.load(Ordering::SeqCst), expected);
        assert_eq!(run.state().get::<u64>("output"), Some(&42));
        assert_eq!(run.current_step().0, "start");
        assert!(run.trace().entries.is_empty());
    }
}

#[test]
fn missing_early_state_binding_sources_prevent_actions() {
    for source in [
        ValueSource::Input { name: "absent".into() },
        ValueSource::State { field: "source".into() }.at("/absent"),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let step = StructuredStepBuilder::new()
            .bind(source, BindingTarget::State { field: "output".into() })
            .action_with_config("effect", (), move |_, _, &()| {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .next("done")
            .build()
            .unwrap();
        let mut run = scope(
            step,
            State::builder()
                .field("source", "Source", json!({}))
                .field("output", "Output", 42_u64)
                .build()
                .unwrap(),
        );
        assert!(
            run.advance()
                .unwrap_err()
                .to_string()
                .contains("missing binding source")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(run.state().get::<u64>("output"), Some(&42));
        assert_eq!(run.current_step().0, "start");
        assert!(run.trace().entries.is_empty());
    }
}

#[test]
fn logical_model_outputs_follow_caller_bindings_and_validate_before_actions() {
    let base = StructuredStepBuilder::new()
        .with_model(ModelTemplate::new(
            "Count",
            vec![(Some("done".into()), "Done".into())],
            vec![],
        ))
        .model_output::<u64>("count", "/0/count", "Return a count")
        .action_with_config("increment", (), |context, _, &()| {
            Ok(vec![Count {
                count: context.proposed::<u64>("count")? + 1,
            }])
        })
        .result::<Vec<Count>>()
        .next("done");
    let unbound: StepConfiguration = serde_json::from_str(&base.to_json().unwrap()).unwrap();
    assert_eq!(unbound.data.model_outputs["count"].criterion, "Return a count");
    assert!(unbound.model.unwrap().state_updates.is_empty());
    assert!(base.clone().build().is_err());
    let result_source = |pointer: &str| ValueSource::Result {
        pointer: pointer.into(),
    };
    for (field, source) in [
        ("direct_count", result_source("/0/count")),
        ("selected_count", result_source("").at("/0/count")),
        ("nested_count", result_source("/0").at("/count")),
        ("chained_count", result_source("").at("/0").at("/count")),
        ("empty_selector", result_source("/0/count").at("")),
    ] {
        let builder = base.clone().bind(source, BindingTarget::State { field: field.into() });
        let saved = builder.to_json().unwrap();
        let exported: StepConfiguration = serde_json::from_str(&saved).unwrap();
        let step = builder.build().unwrap();
        assert_eq!(step.to_json().unwrap(), saved);
        let run = scope(
            step.clone(),
            State::builder().field(field, "Counter", 0_u64).build().unwrap(),
        );
        let TemplateSpec::Template(model) = step.model_template(&run) else {
            panic!("expected model")
        };
        assert_eq!(
            model.state_update_criteria,
            vec![(field.into(), "Return a count".into())]
        );
        assert_eq!(exported.model.unwrap().state_updates, model.state_update_criteria);
        let mut updates = StateUpdates::default();
        updates.set(field.into(), Some(Box::new(8_u64)));
        let mut proposal = TurnProposal::Advance {
            next: Some("done".into()),
            updates,
        };
        step.finalize(&run, &mut proposal).unwrap();
        let TurnProposal::Advance { updates, .. } = proposal else {
            unreachable!()
        };
        assert_eq!(updates.get::<u64>(field), Some(&9));
        let mut missing = TurnProposal::Advance {
            next: Some("done".into()),
            updates: StateUpdates::default(),
        };
        assert!(step.finalize(&run, &mut missing).is_err());
    }
    let duplicate = base.clone().update("count", "/0/count").with_model(ModelTemplate::new(
        "Count",
        vec![],
        vec![("count".into(), "Already declared".into())],
    ));
    for error in [duplicate.to_json().unwrap_err(), duplicate.build().err().unwrap()] {
        assert!(error.contains("duplicate model State destination"), "{error}");
    }
    let ambiguous = base.update("one", "/0/count").bind(
        result_source("").at("/0").at("/count"),
        BindingTarget::State { field: "two".into() },
    );
    let error = ambiguous
        .build()
        .err()
        .expect("equivalent result paths must remain ambiguous");
    assert!(
        error.contains("requires exactly one result-to-State binding"),
        "{error}"
    );
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
struct NonemptyText(#[schemars(length(min = 1))] String);

impl lyquid_flow::Value for NonemptyText {
    fn encode(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn decode(&self, encoded: &str) -> Result<Box<dyn lyquid_flow::Value>, String> {
        serde_json::from_str::<Self>(encoded)
            .map(|value| Box::new(value) as Box<dyn lyquid_flow::Value>)
            .map_err(|error| error.to_string())
    }

    fn clone_box(&self) -> Box<dyn lyquid_flow::Value> {
        Box::new(self.clone())
    }
}

#[test]
fn model_output_constraints_validate_the_proposal_instead_of_initial_state() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let step = StructuredStepBuilder::new()
        .with_model(ModelTemplate::new(
            "Describe",
            vec![(Some("done".into()), "Done".into())],
            vec![],
        ))
        .model_output::<NonemptyText>("text", "", "Return nonempty text")
        .action_with_config("consume", (), move |context, _, &()| {
            counted.fetch_add(1, Ordering::SeqCst);
            context.proposed::<NonemptyText>("text")
        })
        .result::<NonemptyText>()
        .update("description", "")
        .next("done")
        .build()
        .unwrap();
    let run = scope(
        step.clone(),
        State::builder()
            .field("description", "Description", NonemptyText(String::new()))
            .build()
            .unwrap(),
    );
    assert!(matches!(step.model_template(&run), TemplateSpec::Template(_)));
    for (text, expected_calls) in [("", 0), ("Valid", 1)] {
        let mut updates = StateUpdates::default();
        updates.set("description".into(), Some(Box::new(NonemptyText(text.into()))));
        let mut proposal = TurnProposal::Advance {
            next: Some("done".into()),
            updates,
        };
        let result = step.finalize(&run, &mut proposal);
        assert_eq!(result.is_ok(), !text.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
        if let TurnProposal::Advance { updates, .. } = proposal {
            assert_eq!(updates.get::<NonemptyText>("description").unwrap().0, text);
        }
    }
}

#[test]
fn build_and_export_reject_invalid_action_bindings_without_execution() {
    let named = |name| {
        StructuredStepBuilder::new().action_named_with_config(
            name,
            "unused",
            (),
            |_, _, &()| -> Result<Value, String> { panic!("construction must not run actions") },
        )
    };
    for (builder, message) in [
        (named(""), "nonblank and unique"),
        (
            named("saved").action_named_with_config("saved", "identity", (), |_, value, &()| Ok(value)),
            "nonblank and unique",
        ),
        (
            named("saved").update_from(
                "output",
                ValueSource::ActionResult {
                    action: "missing".into(),
                    pointer: "".into(),
                }
                .at("/count"),
            ),
            "unknown action result",
        ),
        (
            named("saved").update_from("output", ValueSource::ModelResponse { pointer: "".into() }.at("/text")),
            "require a model template",
        ),
    ] {
        for error in [builder.to_json().unwrap_err(), builder.build().err().unwrap()] {
            assert!(error.contains(message), "{error}");
        }
    }
}

#[test]
fn export_preserves_action_settings_without_executing_callbacks() {
    let step = StructuredStepBuilder::new()
        .data_default("count", 7_u64)
        .action_named_with_config("first", "add", 2_u64, |context, _, amount| {
            Ok(context["count"].as_u64().unwrap() + amount)
        })
        .action_with_config("multiply", 3_u64, |context, previous, factor| {
            assert_eq!(context.result("first"), Some(&json!(previous)));
            Ok(previous * factor)
        })
        .result::<u64>()
        .update("output", "")
        .next("done");
    let saved = step.to_json().unwrap();
    let definition: StepConfiguration = serde_json::from_str(&saved).unwrap();
    assert_eq!(definition.to_json().unwrap(), saved);
    let mut run = scope(
        step.build().unwrap(),
        State::builder().field("output", "Output", 0_u64).build().unwrap(),
    );
    run.advance().unwrap();
    assert_eq!(run.state().get::<u64>("output"), Some(&27));
    let factory = StructuredStepBuilder::new()
        .with_data_input_factory_config("input", (), |_, _| panic!("not during build/export"));
    assert!(factory.to_json().is_ok());
    assert!(factory.build().is_ok());
    let opaque =
        StructuredStepBuilder::new().with_context(|_: Value| -> Result<Value, String> { panic!("not during export") });
    assert!(opaque.to_json().is_err());
    assert!(opaque.build().is_ok());
}
