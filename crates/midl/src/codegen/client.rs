//! Client stub code generation
//!
//! Generates client proxy classes that wrap DceRpcClient.

use crate::error::Result;
use crate::semantic::{AnalyzedFile, AnalyzedInterface, AnalyzedMethod, AnalyzedParam, ResolvedTypeKind};
use crate::ast::ParamDirection;
use proc_macro2::TokenStream;
use quote::{quote, format_ident};
use super::types::type_to_rust;

/// Generate client stub for an interface
pub fn generate_client(iface: &AnalyzedInterface, _file: &AnalyzedFile) -> Result<TokenStream> {
    if iface.is_local {
        // Local interfaces have no network stubs
        return Ok(quote! {});
    }

    let client_name = format_ident!("{}Client", &iface.name);
    let trait_name = format_ident!("{}", &iface.name);
    let uuid_const = format_ident!("{}_UUID", iface.name.to_uppercase());
    let version_const = format_ident!("{}_VERSION", iface.name.to_uppercase());

    // Generate method implementations
    let methods: Vec<_> = iface.methods.iter()
        .map(|m| generate_client_method(m, iface))
        .collect();

    // Generate trait definition
    let trait_methods: Vec<_> = iface.methods.iter()
        .map(|m| generate_trait_method(m))
        .collect();

    Ok(quote! {
        /// Client trait for #trait_name interface
        #[async_trait::async_trait]
        pub trait #trait_name: Send + Sync {
            #(#trait_methods)*
        }

        /// Client stub for #trait_name interface
        pub struct #client_name {
            inner: dcerpc::DceRpcClient,
        }

        impl #client_name {
            /// Create a new client from an existing DceRpcClient
            pub fn new(client: dcerpc::DceRpcClient) -> Self {
                Self { inner: client }
            }

            /// Connect to a server and create a client
            pub async fn connect(addr: std::net::SocketAddr) -> dcerpc::Result<Self> {
                let interface = dcerpc::SyntaxId::new(
                    dcerpc::Uuid::parse(#uuid_const).unwrap(),
                    #version_const.0,
                    #version_const.1,
                );
                let client = dcerpc::DceRpcClient::connect(addr, interface).await?;
                Ok(Self::new(client))
            }

            /// Get a reference to the underlying client
            pub fn inner(&self) -> &dcerpc::DceRpcClient {
                &self.inner
            }

            #(#methods)*
        }
    })
}

/// Generate a client method implementation
fn generate_client_method(method: &AnalyzedMethod, iface: &AnalyzedInterface) -> TokenStream {
    let method_name = format_ident!("{}", to_snake_case(&method.name));
    let opnum_mod = format_ident!("{}_opnum", iface.name.to_lowercase());
    let opnum_const = format_ident!("{}", method.name.to_uppercase());

    // Determine parameter list
    let in_params: Vec<_> = method.params.iter()
        .filter(|p| p.direction != ParamDirection::Out)
        .collect();

    let out_params: Vec<_> = method.params.iter()
        .filter(|p| p.direction == ParamDirection::Out || p.is_retval)
        .collect();

    // Generate parameter declarations
    let param_decls: Vec<_> = in_params.iter().map(|p| {
        let name = format_ident!("{}", &p.name);
        let ty = type_to_rust(&p.ty.kind);
        quote! { #name: #ty }
    }).collect();

    // Determine return type
    let return_type = determine_return_type(method);

    // Generate encoding code
    let encode_code = generate_encode_code(&in_params);

    // Generate decoding code
    let decode_code = generate_decode_code(&out_params, &method.return_type);

    quote! {
        /// Call #method_name operation
        pub async fn #method_name(&self, #(#param_decls),*) -> dcerpc::Result<#return_type> {
            #encode_code

            let response = self.inner.call(#opnum_mod::#opnum_const, stub_data).await?;

            #decode_code
        }
    }
}

/// Generate trait method signature
fn generate_trait_method(method: &AnalyzedMethod) -> TokenStream {
    let method_name = format_ident!("{}", &method.name);

    // Determine parameter list (all parameters for trait)
    let params: Vec<_> = method.params.iter().map(|p| {
        let name = format_ident!("{}", &p.name);
        let ty = type_to_rust(&p.ty.kind);
        match p.direction {
            ParamDirection::In => quote! { #name: #ty },
            ParamDirection::Out => quote! { #name: &mut #ty },
            ParamDirection::InOut => quote! { #name: &mut #ty },
        }
    }).collect();

    // Determine return type
    let return_type = determine_trait_return_type(method);

    quote! {
        async fn #method_name(&self, #(#params),*) -> dcerpc::Result<#return_type>;
    }
}

/// Determine the return type for a client method
fn determine_return_type(method: &AnalyzedMethod) -> TokenStream {
    let has_return = !matches!(method.return_type.kind, ResolvedTypeKind::Void);
    let out_params: Vec<_> = method.params.iter()
        .filter(|p| p.direction == ParamDirection::Out && !p.is_retval)
        .collect();

    let retval_param = method.params.iter().find(|p| p.is_retval);

    if out_params.is_empty() && retval_param.is_none() {
        if has_return {
            type_to_rust(&method.return_type.kind)
        } else {
            quote! { () }
        }
    } else if out_params.len() == 1 && !has_return && retval_param.is_none() {
        type_to_rust(&out_params[0].ty.kind)
    } else {
        let mut types = Vec::new();
        if has_return {
            types.push(type_to_rust(&method.return_type.kind));
        }
        for p in &out_params {
            types.push(type_to_rust(&p.ty.kind));
        }
        if let Some(rv) = retval_param {
            types.push(type_to_rust(&rv.ty.kind));
        }
        quote! { (#(#types),*) }
    }
}

/// Determine the return type for a trait method
fn determine_trait_return_type(method: &AnalyzedMethod) -> TokenStream {
    let has_return = !matches!(method.return_type.kind, ResolvedTypeKind::Void);
    let retval_param = method.params.iter().find(|p| p.is_retval);

    if has_return {
        type_to_rust(&method.return_type.kind)
    } else if let Some(rv) = retval_param {
        type_to_rust(&rv.ty.kind)
    } else {
        quote! { () }
    }
}

/// Generate encoding code for input parameters
fn generate_encode_code(params: &[&AnalyzedParam]) -> TokenStream {
    if params.is_empty() {
        return quote! {
            let stub_data = Bytes::new();
        };
    }

    let encodings: Vec<_> = params.iter().map(|p| {
        let name = format_ident!("{}", &p.name);
        quote! {
            #name.ndr_encode(&mut buf, &ctx, &mut position)?;
        }
    }).collect();

    quote! {
        let mut buf = BytesMut::new();
        let ctx = NdrContext::default();
        let mut position: usize = 0;

        #(#encodings)*

        let stub_data = buf.freeze();
    }
}

/// Generate decoding code for output parameters and return value
fn generate_decode_code(out_params: &[&AnalyzedParam], return_type: &crate::semantic::ResolvedType) -> TokenStream {
    let has_return = !matches!(return_type.kind, ResolvedTypeKind::Void);

    let mut decodings = Vec::new();
    let mut result_names = Vec::new();

    for p in out_params {
        if !p.is_retval {
            let name = format_ident!("{}", &p.name);
            let ty = type_to_rust(&p.ty.kind);
            decodings.push(quote! {
                let #name = <#ty as NdrDecode>::ndr_decode(&mut cursor, &ctx, &mut position)?;
            });
            result_names.push(name);
        }
    }

    // Handle retval
    let retval = out_params.iter().find(|p| p.is_retval);
    if let Some(rv) = retval {
        let name = format_ident!("{}", &rv.name);
        let ty = type_to_rust(&rv.ty.kind);
        decodings.push(quote! {
            let #name = <#ty as NdrDecode>::ndr_decode(&mut cursor, &ctx, &mut position)?;
        });
        result_names.push(name);
    }

    // Handle return value
    if has_return {
        let ret_ty = type_to_rust(&return_type.kind);
        decodings.push(quote! {
            let _return_value = <#ret_ty as NdrDecode>::ndr_decode(&mut cursor, &ctx, &mut position)?;
        });
    }

    // Build result
    let result = if result_names.is_empty() {
        if has_return {
            quote! { _return_value }
        } else {
            quote! { () }
        }
    } else if result_names.len() == 1 && !has_return {
        let name = &result_names[0];
        quote! { #name }
    } else {
        if has_return {
            quote! { (_return_value, #(#result_names),*) }
        } else if result_names.len() == 1 {
            let name = &result_names[0];
            quote! { #name }
        } else {
            quote! { (#(#result_names),*) }
        }
    };

    quote! {
        let ctx = NdrContext::default();
        let mut cursor = response.as_ref();
        let mut position: usize = 0;

        #(#decodings)*

        Ok(#result)
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
    fn test_generate_client() {
        let input = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface ICalculator {
                long Add([in] long a, [in] long b);
                long Divide([in] long a, [in] long b, [out] long* remainder);
            }
        "#;

        let file = parser::parse(input).unwrap();
        let analyzed = semantic::analyze(&file).unwrap();

        let code = generate_client(&analyzed.interfaces[0], &analyzed).unwrap();
        let code_str = code.to_string();

        assert!(code_str.contains("ICalculatorClient"));
        assert!(code_str.contains("add"));
        assert!(code_str.contains("divide"));
    }
}
