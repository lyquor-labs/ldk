#![doc = include_str!("README.md")]

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub(crate) mod json_schema;
pub use crate::error::Error;

/// A type declaration for Flow data, independent of Rust type identity.
///
/// Describes allowed data for direct validation. This is separate from the
/// runtime `serde_json::Value`, which stores the data.
///
/// Mapping accepts arbitrary string keys with a common value type. Use Mapping(Dynamic)
/// for heterogeneous objects; their consumers are responsible for field-level validation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case", deny_unknown_fields)]
pub enum Type {
    /// Defer further validation to the consumer. Use [`Type::infer`] to inspect a value's current shape.
    Dynamic,
    Boolean,
    /// An integer represented as a JSON integer, within the corresponding Rust range.
    U32,
    U64,
    I64,
    /// Any finite JSON number, decoded as f64 by native consumers.
    F64,
    String,
    /// A nullable value: JSON null or a value satisfying the inner type.
    Option(Box<Self>),
    List(Box<Self>),
    Mapping(Box<Self>),
}

impl Type {
    // TODO: Add JSON Schema export when an external integration needs it.

    /// Infer a type describing a JSON value's current structural shape.
    ///
    /// Null infers Dynamic. Empty or heterogeneous arrays and objects infer List(Dynamic)
    /// and Mapping(Dynamic); homogeneous collections retain their common inferred value type.
    /// Numeric inference uses U64 for nonnegative integer storage, I64 for negative integer
    /// storage, and F64 for floating-point storage. Narrower widths require a declaration.
    pub fn infer(value: &JsonValue) -> Self {
        match value {
            JsonValue::Null => Self::Dynamic,
            JsonValue::Bool(_) => Self::Boolean,
            JsonValue::Number(number) if number.is_u64() => Self::U64,
            JsonValue::Number(number) if number.is_i64() => Self::I64,
            JsonValue::Number(_) => Self::F64,
            JsonValue::String(_) => Self::String,
            JsonValue::Array(values) => Self::List(Box::new(Self::infer_items(values.iter()))),
            JsonValue::Object(values) => Self::Mapping(Box::new(Self::infer_items(values.values()))),
        }
    }

    fn infer_items<'a>(values: impl Iterator<Item = &'a JsonValue>) -> Self {
        let mut types = values.map(Self::infer);
        let item = types.next().unwrap_or(Self::Dynamic);
        if types.all(|ty| ty == item) {
            item
        } else {
            Self::Dynamic
        }
    }

    /// Check JSON data without changing it or interpreting any JSON Schema.
    pub fn validate(&self, value: &JsonValue) -> Result<(), Error> {
        self.validate_at(value, "")
    }

    fn validate_at(&self, value: &JsonValue, path: &str) -> Result<(), Error> {
        match (self, value) {
            (Self::Dynamic, _) |
            (Self::Option(_), JsonValue::Null) |
            (Self::Boolean, JsonValue::Bool(_)) |
            (Self::F64, JsonValue::Number(_)) |
            (Self::String, JsonValue::String(_)) => Ok(()),
            (Self::Option(inner), _) => inner.validate_at(value, path),
            (Self::U32, JsonValue::Number(number)) if number.as_u64().is_some_and(|n| u32::try_from(n).is_ok()) => {
                Ok(())
            }
            (Self::U64, JsonValue::Number(number)) if number.is_u64() => Ok(()),
            (Self::I64, JsonValue::Number(number)) if number.is_i64() => Ok(()),
            (Self::List(item), JsonValue::Array(values)) => {
                for (index, value) in values.iter().enumerate() {
                    item.validate_at(value, &child_path(path, &index.to_string()))?;
                }
                Ok(())
            }
            (Self::Mapping(item), JsonValue::Object(values)) => {
                for (name, value) in values {
                    item.validate_at(value, &child_path(path, name))?;
                }
                Ok(())
            }
            _ => Err(Error::new(path, format!("expected {}", self.kind()))),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Dynamic => "dynamic",
            Self::Boolean => "boolean",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I64 => "i64",
            Self::F64 => "f64",
            Self::String => "string",
            Self::Option(_) => "option",
            Self::List(_) => "list",
            Self::Mapping(_) => "mapping",
        }
    }
}

pub(crate) fn escape_pointer(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

fn child_path(parent: &str, name: &str) -> String {
    format!("{parent}/{}", escape_pointer(name))
}

#[cfg(test)] mod tests;
