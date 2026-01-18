//! Code Generation
//!
//! Generates Rust code from analyzed MIDL definitions.

mod types;
mod ndr;
mod client;
mod server;

use crate::error::{MidlError, Result};
use crate::semantic::AnalyzedFile;
use proc_macro2::TokenStream;
use quote::{quote, format_ident};

/// Code generation options
#[derive(Debug, Clone, Default)]
pub struct CodegenOptions {
    /// Generate client stubs
    pub generate_client: bool,
    /// Generate server stubs
    pub generate_server: bool,
    /// Generate type definitions
    pub generate_types: bool,
}

/// Generate Rust code from an analyzed file
pub fn generate(file: &AnalyzedFile, options: &CodegenOptions) -> Result<String> {
    let mut tokens = TokenStream::new();

    // Generate imports
    tokens.extend(generate_imports());

    // Generate type definitions
    if options.generate_types {
        for ty in &file.types {
            tokens.extend(types::generate_type(ty)?);
        }
    }

    // Generate interface code
    for iface in &file.interfaces {
        // Interface constants (UUID, version, opnums)
        tokens.extend(generate_interface_consts(iface));

        // Client stubs
        if options.generate_client {
            tokens.extend(client::generate_client(iface, file)?);
        }

        // Server stubs
        if options.generate_server {
            tokens.extend(server::generate_server(iface, file)?);
        }
    }

    Ok(prettyplease::unparse(&syn::parse2(tokens).map_err(|e| {
        MidlError::codegen(format!("failed to parse generated code: {}", e))
    })?))
}

/// Generate common imports
fn generate_imports() -> TokenStream {
    quote! {
        #[allow(unused_imports)]
        use bytes::{Buf, BufMut, Bytes, BytesMut};
        #[allow(unused_imports)]
        use midl_ndr::{NdrContext, NdrEncode, NdrDecode, Result as NdrResult};
    }
}

/// Generate interface constants
fn generate_interface_consts(iface: &crate::semantic::AnalyzedInterface) -> TokenStream {
    let name = &iface.name;
    let name_upper = name.to_uppercase();
    let uuid_const = format_ident!("{}_UUID", name_upper);
    let version_const = format_ident!("{}_VERSION", name_upper);

    let uuid_value = iface.uuid.as_deref().unwrap_or("00000000-0000-0000-0000-000000000000");
    let (major, minor) = iface.version;

    let mut tokens = quote! {
        pub const #uuid_const: &str = #uuid_value;
        pub const #version_const: (u16, u16) = (#major, #minor);
    };

    // Generate opnum constants
    if !iface.methods.is_empty() {
        let opnum_mod = format_ident!("{}_opnum", name.to_lowercase());
        let opnum_consts: Vec<_> = iface.methods.iter().map(|m| {
            let opnum_name = format_ident!("{}", m.name.to_uppercase());
            let opnum_value = m.opnum;
            quote! { pub const #opnum_name: u16 = #opnum_value; }
        }).collect();

        tokens.extend(quote! {
            pub mod #opnum_mod {
                #(#opnum_consts)*
            }
        });
    }

    tokens
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parser, semantic};

    #[test]
    fn test_generate_simple_interface() {
        let input = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface ICalculator {
                long Add([in] long a, [in] long b);
            }
        "#;

        let file = parser::parse(input).unwrap();
        let analyzed = semantic::analyze(&file).unwrap();
        let options = CodegenOptions {
            generate_client: true,
            generate_server: true,
            generate_types: true,
        };

        let code = generate(&analyzed, &options).unwrap();
        assert!(code.contains("ICALCULATOR_UUID"));
        assert!(code.contains("ICalculatorClient"));
    }
}
