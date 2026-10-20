use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use lyquid_flow::{InputSpec, State};
use lyquid_test::test;
use serde_json::{Value, json};

use crate::{BindingTarget, StructuredStepBuilder, ValueSource};

fn input(mut field: Value, optional: bool) -> InputSpec {
    let mut builder = InputSpec::builder();
    let node = builder.field("reply", "Reply", Value::Null).json_input();
    let mut specification = serde_json::to_value(builder.finish(node).unwrap()).unwrap();
    if let Some(definitions) = field.as_object_mut().and_then(|field| field.remove("$defs")) {
        specification["schema"]["$defs"] = definitions;
    }
    specification["schema"]["properties"]["reply"] = field;
    if optional {
        specification["schema"]["required"] = json!([]);
    }
    serde_json::from_value(specification).unwrap()
}

fn count(input: InputSpec, source: ValueSource) -> StructuredStepBuilder {
    StructuredStepBuilder::new()
        .data::<u64>("count")
        .with_input(input)
        .bind_data("count", source)
}

fn rejects(builder: StructuredStepBuilder, message: &str) {
    let exported = builder.to_json().unwrap_err();
    let built = builder.build().err().expect("invalid binding must fail build");
    for error in [exported, built] {
        assert!(error.contains(message), "{error}");
        assert!(error.contains("input"), "{error}");
    }
}

#[test]
fn static_input_rejects_unknown_fields_for_context_and_state() {
    for source in [
        ValueSource::Input { name: "missing".into() },
        ValueSource::InputOr {
            name: "missing".into(),
            default: json!(0),
        },
    ] {
        rejects(count(input(json!({"type": "integer"}), false), source), "missing");
    }
    rejects(
        StructuredStepBuilder::new()
            .with_input(input(json!({"type": "integer"}), false))
            .bind(
                ValueSource::Input { name: "missing".into() },
                BindingTarget::State { field: "output".into() },
            ),
        "unknown input field",
    );
}

#[test]
fn static_input_rejects_disjoint_declared_types_and_resolves_references() {
    let mut native = InputSpec::builder();
    let node = native.field("reply", "Reply", String::new()).text_input();
    rejects(
        count(
            native.finish(node).unwrap(),
            ValueSource::Input { name: "reply".into() },
        ),
        "incompatible declared types",
    );
    for schema in [
        json!({"type": "string"}),
        json!({"$ref": "#/$defs/any", "type": "string", "$defs": {"any": true}}),
        json!({"type": "boolean"}),
        json!({"type": "object"}),
        json!({"type": "array"}),
        json!({"type": ["null", "string"]}),
        json!({"anyOf": [{"type": "string"}, {"type": "boolean"}]}),
        json!({"oneOf": [{"type": "null"}, {"type": "string"}]}),
        json!({"allOf": [{"$ref": "#/$defs/text"}], "$defs": {"text": {"type": "string"}}}),
    ] {
        rejects(
            count(input(schema, false), ValueSource::Input { name: "reply".into() }),
            "incompatible declared types",
        );
    }
    let source = ValueSource::Input { name: "reply".into() };
    let target_reference = StructuredStepBuilder::new()
        .data_schema(
            "count",
            json!({"$ref": "#/$defs/count", "$defs": {"count": {"type": "integer"}}}),
            crate::Presence::Required,
        )
        .with_input(input(json!({"type": "string"}), false))
        .bind_data("count", source);
    rejects(target_reference, "count");
}

#[test]
fn static_input_checks_nested_projections_without_requiring_array_values() {
    let schema = json!({
        "$ref": "#/$defs/payload",
        "$defs": {
            "payload": {"type": "object", "properties": {"items": {"type": "array", "items": {"$ref": "#/$defs/item"}}}, "additionalProperties": false},
            "item": {"type": "object", "properties": {"count": {"type": "integer"}}, "additionalProperties": false}
        }
    });
    let source = ValueSource::Input { name: "reply".into() };
    let valid = count(input(schema.clone(), false), source.clone().at("/items").at("/0/count"));
    assert!(valid.to_json().is_ok());
    assert!(valid.build().is_ok());
    for pointer in [
        "/missing",
        "/items/0/missing",
        "/items/0/count/child",
        "/items/01",
        "/items/+1",
    ] {
        rejects(count(input(schema.clone(), false), source.clone().at(pointer)), pointer);
    }
    rejects(
        StructuredStepBuilder::new()
            .data::<String>("count")
            .with_input(input(schema, false))
            .bind_data("count", source.at("/items/0/count")),
        "incompatible declared types",
    );
    let tuple = json!({"type": "array", "prefixItems": [{"type": "integer"}, {"type": "string"}], "items": false});
    rejects(
        count(
            input(tuple.clone(), false),
            ValueSource::Input { name: "reply".into() }.at("/1"),
        ),
        "incompatible declared types",
    );
    rejects(
        count(
            input(tuple, false),
            ValueSource::Input { name: "reply".into() }.at("/2"),
        ),
        "forbids",
    );
    rejects(
        count(
            input(
                json!({"type": "array", "items": {"type": "integer"}, "maxItems": 0}),
                false,
            ),
            ValueSource::Input { name: "reply".into() }.at("/0"),
        ),
        "no index",
    );
    assert!(count(
        input(json!({"type": "object", "properties": {"a/b": {"type": "object", "properties": {"~": {"type": "integer"}}}}}), false),
        ValueSource::Input { name: "reply".into() }.at("/a~1b/~0"),
    ).build().is_ok());
}

#[test]
fn static_input_validates_reachable_fallbacks_using_argument_constraints() {
    let source = ValueSource::InputOr {
        name: "reply".into(),
        default: json!(256),
    };
    rejects(
        StructuredStepBuilder::new()
            .data::<u8>("count")
            .with_input(input(json!({"type": "integer"}), true))
            .bind_data("count", source.clone()),
        "fallback",
    );
    // A required field is always supplied; its fallback is unreachable.
    assert!(
        StructuredStepBuilder::new()
            .data::<u8>("count")
            .with_input(input(json!({"type": "integer"}), false))
            .bind_data("count", source)
            .build()
            .is_ok()
    );
    let nested = json!({"type": "object", "properties": {"count": {"type": "integer"}}});
    rejects(
        count(
            input(nested.clone(), true),
            ValueSource::InputOr {
                name: "reply".into(),
                default: json!({"count": "bad"}),
            }
            .at("/count"),
        ),
        "fallback",
    );
    assert!(
        count(
            input(nested, true),
            ValueSource::InputOr {
                name: "reply".into(),
                default: json!({"count": 7})
            }
            .at("/count")
        )
        .build()
        .is_ok()
    );
}

#[test]
fn static_input_leaves_overlapping_or_unknown_types_for_runtime() {
    for schema in [
        json!({"type": "number"}),
        json!({"type": ["integer", "null"]}),
        json!({"anyOf": [{"type": "integer"}, {"type": "string"}]}),
        json!({"minimum": 0}),
        json!(true),
    ] {
        let builder = count(input(schema, false), ValueSource::Input { name: "reply".into() });
        assert!(builder.to_json().is_ok());
        assert!(builder.build().is_ok());
    }
    // An unconstrained property and conditional shapes need an actual value.
    for schema in [
        json!({"type": "object", "additionalProperties": true}),
        json!({"anyOf": [{"type": "object", "properties": {"count": {"type": "integer"}}}, {"type": "null"}]}),
    ] {
        assert!(
            count(
                input(schema, false),
                ValueSource::Input { name: "reply".into() }.at("/count")
            )
            .build()
            .is_ok()
        );
    }
}

#[test]
fn static_and_dynamic_inputs_retain_runtime_validation_and_atomic_failure() {
    for dynamic in [false, true] {
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let action_calls = Arc::new(AtomicUsize::new(0));
        let counted = action_calls.clone();
        let spec = input(json!({"type": ["integer", "string"]}), false);
        let builder = StructuredStepBuilder::new()
            .data::<u64>("count")
            .bind_input("count", "reply")
            .action_with_config("count", (), move |_, value, &()| {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(value)
            })
            .update("output", "/count")
            .next("done");
        let builder = if dynamic {
            let counted = factory_calls.clone();
            builder.with_input_factory_config("ask", (), move |_, &()| {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(spec.clone())
            })
        } else {
            builder.with_input(spec)
        };
        assert!(builder.to_json().is_ok());
        let step = builder.build().unwrap();
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert_eq!(action_calls.load(Ordering::SeqCst), 0);
        for (value, succeeds) in [(json!("bad"), false), (json!(-1), false), (json!(8), true)] {
            let mut run = super::scope(
                step.clone(),
                State::builder().field("output", "Output", 42_u64).build().unwrap(),
            );
            run.run_until_input().unwrap().unwrap();
            run.input_handle()
                .submit_input(&json!({"reply": value}).to_string())
                .unwrap();
            let result = run.run_until_input();
            if succeeds {
                result.unwrap();
                assert!(run.is_finished());
                assert_eq!(run.state().get::<u64>("output"), Some(&8));
                assert_eq!(action_calls.load(Ordering::SeqCst), 1);
            } else {
                let error = result.err().expect("invalid argument must fail at runtime").to_string();
                assert!(error.contains("argument count"), "{error}");
                assert_eq!(run.state().get::<u64>("output"), Some(&42));
                assert_eq!(run.current_step().0, "start");
                assert!(run.trace().entries.is_empty());
                assert_eq!(action_calls.load(Ordering::SeqCst), 0);
            }
        }
    }
    let dynamic = count(
        input(json!({"type": "integer"}), false),
        ValueSource::Input { name: "reply".into() },
    )
    .with_input_factory_config("later", (), |_, &()| panic!("must not run during construction"));
    assert!(dynamic.to_json().is_ok());
    assert!(dynamic.build().is_ok());
}
