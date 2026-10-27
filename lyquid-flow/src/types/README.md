# Flow types

`Type` defines the Flow data model. Runtime data is stored in `serde_json::Value` and checked
directly against its declared `Type`. `Type::infer` describes a value's current shape.

Validation borrows the declaration and value without owning or changing either. This module exposes
no public `Variable` holder or `Type::Variable` variant. [`State`](crate::State) privately stores
declarations and values, and uses `Type` to validate initialization and assignments.

## Declare and validate data

```rust
use lyquid_flow::Type;
use serde_json::json;

let product = Type::Mapping(Box::new(Type::Dynamic));
let results = Type::List(Box::new(product));
let data = json!([{"name": "Keyboard", "description": null, "price": 49.99}]);

results.validate(&data)?;
let json_data = serde_json::to_string(&data)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Steps can share the same declaration to validate data. Types compare by
structure. Runtime data uses Serde JSON's arrays, objects and numeric representation.

## Supported types

| Type | Accepted values |
| --- | --- |
| `Boolean`, `String` | The corresponding JSON primitive |
| `U32`, `U64`, `I64` | JSON integer storage within the corresponding Rust range |
| `F64` | Finite JSON numbers consumed as `f64` |
| `List(T)` | Arrays whose elements satisfy `T` |
| `Mapping(T)` | Objects whose values satisfy `T` |
| `Option(T)` | JSON null or a value satisfying `T` |
| `Dynamic` | Any JSON value; further type checking is deferred to its consumer |

Mappings allow arbitrary string keys and apply the same `T` to every value. Use `Mapping(Dynamic)`
for objects containing different value types, as in the product example. Core checks that the value
is an object; its consumer checks any required keys and field-specific types. Use
`Type::Option(Box::new(T))` for JSON null or a value satisfying `T`.
Values must already match the declaration; strings, numbers and booleans remain distinct.
Errors identify the offending field or array index with a JSON Pointer.

`Type::infer(&value)` describes a value's current shape. Null infers `Dynamic`. Empty or heterogeneous
arrays and objects infer `List(Dynamic)` and `Mapping(Dynamic)`, respectively. Homogeneous collections
retain their common inferred value type. Object keys do not become part of the declaration.
Numeric inference returns `U64` for nonnegative integer storage, `I64` for negative integer storage,
and `F64` for floating-point storage, including `1.0`. JSON does not retain the original Rust width;
use an explicit declaration such as `U32` when a narrower range is required.

Use Serde JSON directly to parse and serialize the payload.

## JSON and schemas

JSON numbers use exact `i64`/`u64` integers or finite `f64`. Validation preserves that representation.
Large integers outside the `i64`/`u64` domain may parse as rounded `f64` values. Input parsing follows
Serde JSON's nesting and duplicate-key behavior.

Width-specific integer declarations use integer storage, so a value accepted by `U32`, `U64` or
`I64` can be read with its corresponding native Serde type. Integral floats such as `1.0` are
rejected by these integer declarations. `F64` retains Serde JSON's finite numeric representation.

JSON objects use Serde JSON's default sorted-key storage.

Serializing a `Type` produces its `kind`/`value` declaration for consumers such as model prompts.
Declarations are constructed in Rust; deserialization and JSON Schema generation for declarations
are deferred until a consumer needs them. Exporting the declared data type as a JSON Schema for
its values is also deferred.

`types/json_schema.rs` supplies native Rust schema generation, schema checking and JSON Schema
validation. Input contracts use these utilities for patterns, ranges and recursive schemas.
Core `Type::validate` checks JSON values directly without using these utilities.
Both validators use the shared error in `error.rs`, exposed as `types::Error` and `InputError`.
