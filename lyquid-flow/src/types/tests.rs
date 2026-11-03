use lyquid_test::test;
use serde_json::json;

use super::*;

fn products() -> Type {
    Type::Mapping(Box::new(Type::List(Box::new(Type::Mapping(Box::new(Type::Dynamic))))))
}

#[test]
fn one_structural_declaration_validates_data_from_multiple_producers() {
    let data =
        json!({"product_list": [{"name": "Keyboard", "description": "Compact wireless keyboard", "price": 49.99}]});
    let declaration = products();
    declaration.validate(&data).unwrap();

    // A second producer uses the same structural declaration without any native TypeId.
    declaration.validate(&json!({"product_list": []})).unwrap();
}

#[test]
fn invalid_nested_values_report_their_path() {
    let error = products()
        .validate(&json!({"product_list": ["not an object"]}))
        .unwrap_err();
    assert_eq!(error.path, "/product_list/0");
}

#[test]
fn mappings_allow_nullable_values_without_requiring_keys() {
    let declaration = Type::Mapping(Box::new(Type::Option(Box::new(Type::String))));
    for value in [json!({}), json!({"a": null}), json!({"a": "yes", "b": null})] {
        declaration.validate(&value).unwrap();
    }
    assert_eq!(declaration.validate(&json!({"a": 1})).unwrap_err().path, "/a");
    assert!(declaration.validate(&json!(null)).is_err());
}

#[test]
fn mappings_accept_arbitrary_keys_but_validate_each_value() {
    let declaration = Type::Mapping(Box::new(Type::List(Box::new(Type::Boolean))));
    assert!(declaration.validate(&json!({"a": [true, false], "": []})).is_ok());
    let error = declaration.validate(&json!({"a~/b": [false, 0]})).unwrap_err();
    assert_eq!(error.path, "/a~0~1b/1");
    assert!(declaration.validate(&json!([])).is_err());
}

#[test]
fn numeric_inference_uses_storage_without_coercion() {
    for (value, expected) in [
        (json!(0), Type::U64),
        (json!(u32::MAX), Type::U64),
        (json!(i64::MIN), Type::I64),
        (json!(-1), Type::I64),
        (json!(i64::MAX), Type::U64),
        (json!(u64::MAX), Type::U64),
        (json!(1.0), Type::F64),
        (json!(-0.0), Type::F64),
        (json!(1.5), Type::F64),
    ] {
        let inferred = Type::infer(&value);
        assert_eq!(inferred, expected);
        inferred.validate(&value).unwrap();
    }
}

#[test]
fn numeric_widths_preserve_native_ranges_and_reject_invalid_values() {
    for (declaration, valid, invalid) in [
        (
            Type::U32,
            vec![json!(0), json!(u32::MAX)],
            vec![json!(-1), json!(u64::from(u32::MAX) + 1)],
        ),
        (
            Type::U64,
            vec![json!(0), json!(u64::MAX)],
            vec![json!(-1), json!(18446744073709551616.0)],
        ),
        (
            Type::I64,
            vec![json!(i64::MIN), json!(i64::MAX)],
            vec![json!(u64::MAX), json!(-9223372036854777856.0)],
        ),
    ] {
        for value in valid {
            declaration.validate(&value).unwrap();
            match declaration {
                Type::U32 => {
                    serde_json::from_value::<u32>(value).unwrap();
                }
                Type::U64 => {
                    serde_json::from_value::<u64>(value).unwrap();
                }
                Type::I64 => {
                    serde_json::from_value::<i64>(value).unwrap();
                }
                _ => unreachable!(),
            }
        }
        for value in invalid.into_iter().chain([json!(1.5), json!("1"), json!(null)]) {
            assert!(declaration.validate(&value).is_err());
        }
        // Integer declarations require integer storage, even for mathematically integral floats.
        for value in [json!(1.0), json!(-0.0)] {
            assert!(declaration.validate(&value).is_err());
        }
    }
}

#[test]
fn f64_accepts_finite_numeric_payloads() {
    for value in [json!(f64::MIN), json!(f64::MAX), json!(0.1), json!(u64::MAX)] {
        Type::F64.validate(&value).unwrap();
        assert!(serde_json::from_value::<f64>(value).unwrap().is_finite());
    }
}

#[test]
fn dynamic_accepts_values_of_different_inferred_types() {
    for (value, inferred) in [
        (json!(1), Type::U64),
        (json!("one"), Type::String),
        (json!(null), Type::Dynamic),
    ] {
        Type::Dynamic.validate(&value).unwrap();
        assert_eq!(Type::infer(&value), inferred);
    }
}

#[test]
fn dynamic_mappings_allow_mixed_values_and_changing_keys() {
    let declaration = Type::Mapping(Box::new(Type::Dynamic));
    for value in [
        json!({"value": 1}),
        json!({"name": "Keyboard", "price": 49.99, "details": [null, true]}),
        json!({}),
    ] {
        declaration.validate(&value).unwrap();
    }
    assert!(declaration.validate(&json!([])).is_err());
    assert!(declaration.validate(&json!(null)).is_err());
}

#[test]
fn inferred_types_cover_empty_and_heterogeneous_collections() {
    for value in [
        json!([]),
        json!([1, -1]),
        json!([1, 1.0]),
        json!([1, 1.5]),
        json!([null, 1, "one", 2]),
    ] {
        assert_eq!(Type::infer(&value), Type::List(Box::new(Type::Dynamic)));
    }
    assert_eq!(Type::infer(&json!([1, 2])), Type::List(Box::new(Type::U64)));
    assert_eq!(
        Type::infer(&json!([{"x": true}, {"y": false}])),
        Type::List(Box::new(Type::Mapping(Box::new(Type::Boolean))))
    );
    for data in [
        json!([]),
        json!({}),
        json!([{"x": []}, {"x": null}]),
        json!([true, "x", {"nested": [1, 1.5]}]),
    ] {
        assert!(Type::infer(&data).validate(&data).is_ok());
    }
}

#[test]
fn inferred_mappings_keep_a_common_value_type_without_recording_keys() {
    for (value, item) in [
        (json!({}), Type::Dynamic),
        (json!({"a": 1, "b": 2}), Type::U64),
        (json!({"a": 1, "b": -1}), Type::Dynamic),
        (json!({"a": 1, "b": 1.0}), Type::Dynamic),
        (json!({"a": null, "b": "one"}), Type::Dynamic),
        (
            json!({"a": {"x": true}, "b": {"y": false}}),
            Type::Mapping(Box::new(Type::Boolean)),
        ),
    ] {
        let inferred = Type::infer(&value);
        assert_eq!(inferred, Type::Mapping(Box::new(item)));
        inferred.validate(&value).unwrap();
        inferred.validate(&json!({})).unwrap();
    }
}

#[test]
fn options_validate_nested_values() {
    let declaration = Type::Option(Box::new(Type::List(Box::new(Type::Option(Box::new(Type::String))))));
    declaration.validate(&json!(null)).unwrap();
    declaration.validate(&json!([null, "one"])).unwrap();
    let error = declaration.validate(&json!([null, 2])).unwrap_err();
    assert_eq!(error.path, "/1");
}

#[test]
fn serializes_and_deserializes_type_declarations() {
    for (declaration, json) in [
        (Type::Dynamic, json!({"kind": "dynamic"})),
        (Type::Boolean, json!({"kind": "boolean"})),
        (Type::U32, json!({"kind": "u32"})),
        (Type::U64, json!({"kind": "u64"})),
        (Type::I64, json!({"kind": "i64"})),
        (Type::F64, json!({"kind": "f64"})),
        (Type::String, json!({"kind": "string"})),
        (
            Type::Option(Box::new(Type::List(Box::new(Type::Mapping(Box::new(Type::Dynamic)))))),
            json!({"kind": "option", "value": {"kind": "list", "value": {"kind": "mapping", "value": {"kind": "dynamic"}}}}),
        ),
    ] {
        assert_eq!(serde_json::to_value(&declaration).unwrap(), json);
        assert_eq!(serde_json::from_value::<Type>(json).unwrap(), declaration);
    }
}

#[test]
fn rejects_malformed_type_declarations() {
    for json in [
        json!({}),
        json!({"kind": "unknown"}),
        json!({"kind": "list"}),
        json!({"kind": "list", "value": null}),
        json!({"kind": "string", "extra": true}),
        json!({"kind": "mapping", "value": {"kind": "string", "extra": true}}),
    ] {
        assert!(serde_json::from_value::<Type>(json.clone()).is_err(), "{json}");
    }
}
