//! Phase-neutral diagnostics and the construction error boundary.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// A structural, schema or decoding failure at a JSON Pointer in a JSON value.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{path}: {message}")]
pub struct Error {
    pub path: String,
    pub message: String,
}

impl Error {
    pub(crate) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// One or more failures from shared validation, with no construction or execution policy.
#[derive(Clone, Debug)]
pub struct Diagnostics {
    pub diagnostics: Vec<Diagnostic>,
}

/// Failure to assemble a Flow, Step, or initial State.
#[derive(Clone, Debug, thiserror::Error)]
#[error(transparent)]
pub struct BuildError(#[from] pub Diagnostics);

impl From<Diagnostic> for BuildError {
    fn from(diagnostic: Diagnostic) -> Self {
        Self(diagnostic.into())
    }
}

impl std::fmt::Display for Diagnostics {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            if index != 0 {
                write!(formatter, "; ")?;
            }
            write!(formatter, "{diagnostic}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostics {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // A batch has no single cause; each diagnostic retains its own source.
        match self.diagnostics.as_slice() {
            [diagnostic] => diagnostic.source(),
            _ => None,
        }
    }
}

impl From<String> for Diagnostics {
    fn from(message: String) -> Self {
        Diagnostic::new("", message).into()
    }
}

impl From<&str> for Diagnostics {
    fn from(message: &str) -> Self {
        Diagnostic::new("", message).into()
    }
}

impl From<Diagnostic> for Diagnostics {
    fn from(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostics: vec![diagnostic],
        }
    }
}

impl Diagnostics {
    /// Prefix diagnostic contexts without replacing their original sources.
    pub fn at(mut self, context: impl AsRef<str>) -> Self {
        for diagnostic in &mut self.diagnostics {
            diagnostic.context = if diagnostic.context.is_empty() {
                context.as_ref().to_owned()
            } else {
                format!("{}: {}", context.as_ref(), diagnostic.context)
            };
        }
        self
    }
}

/// A validation or execution diagnostic, without a variant for each message.
/// Context identifies the field, binding, component, or operation that failed.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub context: String,
    pub message: String,
    pub source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.context.is_empty() {
            write!(formatter, "{}: ", self.context)?;
        }
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Diagnostic {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

impl Diagnostic {
    pub fn new(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            context: context.into(),
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(context: impl Into<String>, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            context: context.into(),
            message: format!("{source:#}"),
            source: Some(Arc::new(source)),
        }
    }
}
