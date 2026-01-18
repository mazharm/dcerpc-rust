//! MIDL (Microsoft Interface Definition Language) Compiler
//!
//! This crate provides a compiler for MIDL files, generating Rust code
//! with NDR encoding/decoding for use with the dcerpc crate.
//!
//! # Architecture
//!
//! The compiler pipeline consists of:
//! 1. Lexer: Tokenizes the input IDL file
//! 2. Parser: Builds an AST from tokens
//! 3. Semantic Analysis: Type resolution, validation
//! 4. Code Generation: Produces Rust source code
//!
//! # Example
//!
//! ```ignore
//! use midl::{compile, CompileOptions};
//!
//! let idl = r#"
//!     [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
//!     interface ICalculator {
//!         long Add([in] long a, [in] long b);
//!     }
//! "#;
//!
//! let result = compile(idl, &CompileOptions::default())?;
//! println!("{}", result.rust_code);
//! ```

pub mod lexer;
pub mod parser;
pub mod ast;
pub mod semantic;
pub mod ndr_layout;
pub mod codegen;
mod error;

pub use error::{MidlError, Result};
pub use ast::*;

use codegen::CodegenOptions;

/// Compilation options
#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    /// Generate client stubs
    pub generate_client: bool,
    /// Generate server stubs
    pub generate_server: bool,
    /// Generate type definitions
    pub generate_types: bool,
    /// Module name for generated code
    pub module_name: Option<String>,
}

impl CompileOptions {
    /// Create options for generating everything
    pub fn all() -> Self {
        Self {
            generate_client: true,
            generate_server: true,
            generate_types: true,
            module_name: None,
        }
    }

    /// Create options for client-only generation
    pub fn client_only() -> Self {
        Self {
            generate_client: true,
            generate_server: false,
            generate_types: true,
            module_name: None,
        }
    }

    /// Create options for server-only generation
    pub fn server_only() -> Self {
        Self {
            generate_client: false,
            generate_server: true,
            generate_types: true,
            module_name: None,
        }
    }

    /// Set the module name
    pub fn with_module_name(mut self, name: impl Into<String>) -> Self {
        self.module_name = Some(name.into());
        self
    }
}

/// Compilation result
#[derive(Debug)]
pub struct CompileResult {
    /// Generated Rust source code
    pub rust_code: String,
    /// Interface names found in the IDL
    pub interfaces: Vec<String>,
    /// Type names defined in the IDL
    pub types: Vec<String>,
}

/// Compile an IDL string to Rust code
pub fn compile(idl: &str, options: &CompileOptions) -> Result<CompileResult> {
    // Parse the IDL
    let file = parser::parse(idl)?;

    // Semantic analysis
    let analyzed = semantic::analyze(&file)?;

    // Generate code
    let codegen_opts = CodegenOptions {
        generate_client: options.generate_client,
        generate_server: options.generate_server,
        generate_types: options.generate_types,
    };

    let rust_code = codegen::generate(&analyzed, &codegen_opts)?;

    // Collect interface and type names
    let interfaces: Vec<String> = file
        .items
        .iter()
        .filter_map(|item| {
            if let ast::Item::Interface(iface) = item {
                Some(iface.name.clone())
            } else {
                None
            }
        })
        .collect();

    let types: Vec<String> = file
        .items
        .iter()
        .filter_map(|item| match item {
            ast::Item::Typedef(td) => Some(td.name.clone()),
            ast::Item::Struct(s) => Some(s.name.clone()),
            ast::Item::Enum(e) => Some(e.name.clone()),
            ast::Item::Union(u) => Some(u.name.clone()),
            _ => None,
        })
        .collect();

    Ok(CompileResult {
        rust_code,
        interfaces,
        types,
    })
}

/// Parse an IDL string without generating code (for syntax checking)
pub fn parse(idl: &str) -> Result<ast::File> {
    parser::parse(idl)
}

/// Analyze a parsed IDL file (for semantic checking)
pub fn analyze(file: &ast::File) -> Result<semantic::AnalyzedFile> {
    semantic::analyze(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_interface() {
        let idl = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface ICalculator {
                long Add([in] long a, [in] long b);
            }
        "#;

        let result = compile(idl, &CompileOptions::all()).unwrap();
        assert!(result.interfaces.contains(&"ICalculator".to_string()));
        assert!(result.rust_code.contains("ICalculator"));
    }
}
