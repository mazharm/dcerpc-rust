//! Server stub code generation
//!
//! Generates server trait and InterfaceBuilder code.

use crate::error::Result;
use crate::semantic::{AnalyzedFile, AnalyzedInterface, AnalyzedMethod, AnalyzedParam, ResolvedTypeKind};
use crate::ast::ParamDirection;
use proc_macro2::TokenStream;
use quote::{quote, format_ident};
use super::types::type_to_rust;

/// Generate server stubs for an interface
pub fn generate_server(iface: &AnalyzedInterface, _file: &AnalyzedFile) -> Result<TokenStream> {
    if iface.is_local {
        // Local interfaces have no network stubs
        return Ok(quote! {});
    }

    let trait_name = format_ident!("{}Server", &iface.name);
    let factory_name = format_ident!("create_{}_interface", to_snake_case(&iface.name));
    let uuid_const = format_ident!("{}_UUID", iface.name.to_uppercase());
    let version_const = format_ident!("{}_VERSION", iface.name.to_uppercase());

    // Generate trait methods
    let trait_methods: Vec<_> = iface.methods.iter()
        .map(|m| generate_trait_method(m))
        .collect();

    // Generate operation handlers
    let handlers: Vec<_> = iface.methods.iter()
        .map(|m| generate_operation_handler(m, iface))
        .collect();

    // Generate opnum registrations
    let registrations: Vec<_> = iface.methods.iter().map(|m| {
        let opnum = m.opnum;
        let handler_name = format_ident!("handle_{}", to_snake_case(&m.name));
        quote! {
            .operation(#opnum, {
                let impl_clone = impl_.clone();
                move |stub_data| {
                    let impl_ = impl_clone.clone();
                    Box::pin(#handler_name(impl_, stub_data))
                }
            })
        }
    }).collect();

    Ok(quote! {
        /// Server trait for implementing the interface
        #[async_trait::async_trait]
        pub trait #trait_name: Send + Sync + 'static {
            #(#trait_methods)*
        }

        /// Create a DCE RPC interface from an implementation
        pub fn #factory_name<T: #trait_name>(impl_: std::sync::Arc<T>) -> dcerpc::Interface {
            #(#handlers)*

            dcerpc::InterfaceBuilder::new(#uuid_const, #version_const.0, #version_const.1)
                .unwrap()
                #(#registrations)*
                .build()
        }
    })
}

/// Generate a trait method signature for the server
fn generate_trait_method(method: &AnalyzedMethod) -> TokenStream {
    let method_name = format_ident!("{}", to_snake_case(&method.name));

    // All input parameters
    let in_params: Vec<_> = method.params.iter()
        .filter(|p| p.direction != ParamDirection::Out)
        .map(|p| {
            let name = format_ident!("{}", &p.name);
            let ty = type_to_rust(&p.ty.kind);
            quote! { #name: #ty }
        })
        .collect();

    // Determine return type
    let return_type = determine_return_type(method);

    quote! {
        async fn #method_name(&self, #(#in_params),*) -> dcerpc::Result<#return_type>;
    }
}

/// Generate an operation handler function
fn generate_operation_handler(method: &AnalyzedMethod, iface: &AnalyzedInterface) -> TokenStream {
    let handler_name = format_ident!("handle_{}", to_snake_case(&method.name));
    let method_name = format_ident!("{}", to_snake_case(&method.name));
    let trait_name = format_ident!("{}Server", &iface.name);

    // Input parameters
    let in_params: Vec<_> = method.params.iter()
        .filter(|p| p.direction != ParamDirection::Out)
        .collect();

    // Generate decode code
    let decode_code = generate_decode_code(&in_params);

    // Generate method call arguments
    let call_args: Vec<_> = in_params.iter().map(|p| {
        let name = format_ident!("{}", &p.name);
        quote! { #name }
    }).collect();

    // Generate encode code
    let encode_code = generate_encode_code(&method.params, &method.return_type);

    quote! {
        async fn #handler_name<T: #trait_name>(
            impl_: std::sync::Arc<T>,
            stub_data: Bytes,
        ) -> dcerpc::Result<Bytes> {
            #decode_code

            let result = impl_.#method_name(#(#call_args),*).await?;

            #encode_code
        }
    }
}

/// Generate decode code for server request
fn generate_decode_code(params: &[&AnalyzedParam]) -> TokenStream {
    if params.is_empty() {
        return quote! {
            let _ = stub_data; // unused
        };
    }

    let decodings: Vec<_> = params.iter().map(|p| {
        let name = format_ident!("{}", &p.name);
        let ty = type_to_rust(&p.ty.kind);
        quote! {
            let #name = <#ty as NdrDecode>::ndr_decode(&mut cursor, &ctx, &mut position)?;
        }
    }).collect();

    quote! {
        let ctx = NdrContext::default();
        let mut cursor = stub_data.as_ref();
        let mut position: usize = 0;

        #(#decodings)*
    }
}

/// Generate encode code for server response
fn generate_encode_code(params: &[AnalyzedParam], return_type: &crate::semantic::ResolvedType) -> TokenStream {
    let out_params: Vec<_> = params.iter()
        .filter(|p| p.direction == ParamDirection::Out && !p.is_retval)
        .collect();

    let has_return = !matches!(return_type.kind, ResolvedTypeKind::Void);
    let has_retval = params.iter().any(|p| p.is_retval);

    // Simple case: just return value
    if out_params.is_empty() && !has_retval {
        if has_return {
            let _ret_ty = type_to_rust(&return_type.kind);
            return quote! {
                let mut buf = BytesMut::new();
                let ctx = NdrContext::default();
                let mut position: usize = 0;

                result.ndr_encode(&mut buf, &ctx, &mut position)?;

                Ok(buf.freeze())
            };
        } else {
            return quote! {
                Ok(Bytes::new())
            };
        }
    }

    // Complex case: output parameters and/or return value
    // Use tuple indices: result.0 for return value, result.1, result.2, etc. for out params
    let start_idx = if has_return { 1usize } else { 0usize };
    let encodings: Vec<_> = out_params.iter().enumerate().map(|(i, _p)| {
        let idx = syn::Index::from(start_idx + i);
        quote! {
            result.#idx.ndr_encode(&mut buf, &ctx, &mut position)?;
        }
    }).collect();

    let return_encoding = if has_return {
        if out_params.is_empty() && !has_retval {
            quote! { result.ndr_encode(&mut buf, &ctx, &mut position)?; }
        } else {
            quote! { result.0.ndr_encode(&mut buf, &ctx, &mut position)?; }
        }
    } else {
        quote! {}
    };

    // NDR order: output parameters first, then return value
    quote! {
        let mut buf = BytesMut::new();
        let ctx = NdrContext::default();
        let mut position: usize = 0;

        #(#encodings)*
        #return_encoding

        Ok(buf.freeze())
    }
}

/// Determine the return type for a server method
fn determine_return_type(method: &AnalyzedMethod) -> TokenStream {
    let has_return = !matches!(method.return_type.kind, ResolvedTypeKind::Void);
    let out_params: Vec<_> = method.params.iter()
        .filter(|p| p.direction == ParamDirection::Out && !p.is_retval)
        .collect();
    let retval = method.params.iter().find(|p| p.is_retval);

    // Simple case: just return value or void
    if out_params.is_empty() && retval.is_none() {
        if has_return {
            return type_to_rust(&method.return_type.kind);
        } else {
            return quote! { () };
        }
    }

    // Build tuple of return value + out params + retval
    let mut types = Vec::new();

    if has_return {
        types.push(type_to_rust(&method.return_type.kind));
    }

    for p in &out_params {
        types.push(type_to_rust(&p.ty.kind));
    }

    if let Some(rv) = retval {
        types.push(type_to_rust(&rv.ty.kind));
    }

    if types.len() == 1 {
        types.into_iter().next().unwrap()
    } else {
        quote! { (#(#types),*) }
    }
}

/// Convert PascalCase to snake_case
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(ch.to_lowercase().next().unwrap());
        } else {
            result.push(ch);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parser, semantic};

    #[test]
    fn test_generate_server() {
        let input = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface ICalculator {
                long Add([in] long a, [in] long b);
            }
        "#;

        let file = parser::parse(input).unwrap();
        let analyzed = semantic::analyze(&file).unwrap();

        let code = generate_server(&analyzed.interfaces[0], &analyzed).unwrap();
        let code_str = code.to_string();

        assert!(code_str.contains("ICalculatorServer"));
        assert!(code_str.contains("create_i_calculator_interface"));
    }

    #[test]
    fn test_snake_case() {
        assert_eq!(to_snake_case("ICalculator"), "i_calculator");
        assert_eq!(to_snake_case("Add"), "add");
        assert_eq!(to_snake_case("GetValue"), "get_value");
    }
}
