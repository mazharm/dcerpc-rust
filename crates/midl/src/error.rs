//! MIDL compiler errors

use thiserror::Error;

/// Source location for error reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn at(pos: usize) -> Self {
        Self { start: pos, end: pos }
    }
}

/// MIDL compilation errors
#[derive(Debug, Error)]
pub enum MidlError {
    /// Lexer error
    #[error("lexer error at position {position}: {message}")]
    LexerError {
        position: usize,
        message: String,
    },

    /// Parser error
    #[error("parse error at position {position}: {message}")]
    ParseError {
        position: usize,
        message: String,
    },

    /// Semantic error
    #[error("semantic error: {message}")]
    SemanticError {
        message: String,
        span: Option<Span>,
    },

    /// Undefined type
    #[error("undefined type: {name}")]
    UndefinedType {
        name: String,
        span: Option<Span>,
    },

    /// Duplicate definition
    #[error("duplicate definition: {name}")]
    DuplicateDefinition {
        name: String,
        span: Option<Span>,
    },

    /// Invalid attribute
    #[error("invalid attribute: {message}")]
    InvalidAttribute {
        message: String,
        span: Option<Span>,
    },

    /// Missing required attribute
    #[error("missing required attribute: {attribute} on {target}")]
    MissingAttribute {
        attribute: String,
        target: String,
        span: Option<Span>,
    },

    /// Invalid UUID
    #[error("invalid UUID: {uuid}")]
    InvalidUuid {
        uuid: String,
        span: Option<Span>,
    },

    /// Code generation error
    #[error("code generation error: {message}")]
    CodegenError {
        message: String,
    },
}

/// Result type for MIDL operations
pub type Result<T> = std::result::Result<T, MidlError>;

impl MidlError {
    pub fn lexer(position: usize, message: impl Into<String>) -> Self {
        Self::LexerError {
            position,
            message: message.into(),
        }
    }

    pub fn parse(position: usize, message: impl Into<String>) -> Self {
        Self::ParseError {
            position,
            message: message.into(),
        }
    }

    pub fn semantic(message: impl Into<String>) -> Self {
        Self::SemanticError {
            message: message.into(),
            span: None,
        }
    }

    pub fn semantic_at(message: impl Into<String>, span: Span) -> Self {
        Self::SemanticError {
            message: message.into(),
            span: Some(span),
        }
    }

    pub fn undefined_type(name: impl Into<String>) -> Self {
        Self::UndefinedType {
            name: name.into(),
            span: None,
        }
    }

    pub fn duplicate(name: impl Into<String>) -> Self {
        Self::DuplicateDefinition {
            name: name.into(),
            span: None,
        }
    }

    pub fn codegen(message: impl Into<String>) -> Self {
        Self::CodegenError {
            message: message.into(),
        }
    }
}
