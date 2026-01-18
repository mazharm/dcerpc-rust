//! NDR encode/decode code generation
//!
//! Generates NdrEncode and NdrDecode implementations for generated types.

#[allow(unused_imports)]
use crate::semantic::{ResolvedType, ResolvedTypeKind, PrimitiveType, AnalyzedParam};
use crate::ast::ParamDirection;
use proc_macro2::TokenStream;
use quote::{quote, format_ident};
use super::types::type_to_rust;

/// Generate code to encode a parameter
#[allow(dead_code)]
pub fn generate_param_encode(param: &AnalyzedParam) -> TokenStream {
    let name = format_ident!("{}", &param.name);

    if param.direction == ParamDirection::Out && !matches!(param.direction, ParamDirection::InOut) {
        // Output-only parameters are not sent in the request
        return quote! {};
    }

    // Check for string
    if param.is_string {
        return quote! {
            #name.ndr_encode(&mut buf, &ctx, &mut position)?;
        };
    }

    // Check for size_is
    if let Some(ref size_expr) = param.size_is {
        // Conformant array - need to encode the size first
        let size_ident = format_ident!("{}", size_expr);
        return quote! {
            // Conformance (size) is sent first
            ctx.put_u32(&mut buf, #size_ident as u32);
            position += 4;
            // Then the array data
            for elem in &#name {
                elem.ndr_encode(&mut buf, &ctx, &mut position)?;
            }
        };
    }

    quote! {
        #name.ndr_encode(&mut buf, &ctx, &mut position)?;
    }
}

/// Generate code to decode a parameter
#[allow(dead_code)]
pub fn generate_param_decode(param: &AnalyzedParam) -> TokenStream {
    let name = format_ident!("{}", &param.name);
    let ty = type_to_rust(&param.ty.kind);

    if param.direction == ParamDirection::In {
        // Input-only parameters are not in the response
        return quote! {};
    }

    quote! {
        let #name = <#ty as NdrDecode>::ndr_decode(&mut cursor, &ctx, &mut position)?;
    }
}

/// Generate stub data encoding for a method call
#[allow(dead_code)]
pub fn generate_request_encode(params: &[AnalyzedParam]) -> TokenStream {
    let in_params: Vec<_> = params.iter()
        .filter(|p| p.direction != ParamDirection::Out)
        .collect();

    if in_params.is_empty() {
        return quote! {
            let stub_data = Bytes::new();
        };
    }

    let encodings: Vec<_> = in_params.iter().map(|p| generate_param_encode(p)).collect();

    quote! {
        let mut buf = BytesMut::new();
        let ctx = NdrContext::default();
        let mut position: usize = 0;

        #(#encodings)*

        let stub_data = buf.freeze();
    }
}

/// Generate stub data decoding for a method response
#[allow(dead_code)]
pub fn generate_response_decode(params: &[AnalyzedParam], return_type: &ResolvedType) -> TokenStream {
    let out_params: Vec<_> = params.iter()
        .filter(|p| p.direction != ParamDirection::In || p.is_retval)
        .collect();

    let has_return = !matches!(return_type.kind, ResolvedTypeKind::Void);

    let mut decodings = Vec::new();
    let mut result_names = Vec::new();

    // Decode output parameters
    for p in &out_params {
        let name = format_ident!("{}", &p.name);
        let ty = type_to_rust(&p.ty.kind);

        if !p.is_retval {
            decodings.push(quote! {
                let #name = <#ty as NdrDecode>::ndr_decode(&mut cursor, &ctx, &mut position)?;
            });
        }
        result_names.push(name);
    }

    // Decode return value
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

/// Generate server-side request decoding
#[allow(dead_code)]
pub fn generate_server_request_decode(params: &[AnalyzedParam]) -> TokenStream {
    let in_params: Vec<_> = params.iter()
        .filter(|p| p.direction != ParamDirection::Out)
        .collect();

    if in_params.is_empty() {
        return quote! {};
    }

    let decodings: Vec<_> = in_params.iter().map(|p| {
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

/// Generate server-side response encoding
#[allow(dead_code)]
pub fn generate_server_response_encode(params: &[AnalyzedParam], return_type: &ResolvedType) -> TokenStream {
    let out_params: Vec<_> = params.iter()
        .filter(|p| p.direction != ParamDirection::In)
        .collect();

    let has_return = !matches!(return_type.kind, ResolvedTypeKind::Void);

    let mut encodings = Vec::new();

    // Encode output parameters
    for p in &out_params {
        let name = format_ident!("{}", &p.name);
        encodings.push(quote! {
            #name.ndr_encode(&mut buf, &ctx, &mut position)?;
        });
    }

    // Encode return value
    if has_return {
        encodings.push(quote! {
            result.ndr_encode(&mut buf, &ctx, &mut position)?;
        });
    }

    quote! {
        let mut buf = BytesMut::new();
        let ctx = NdrContext::default();
        let mut position: usize = 0;

        #(#encodings)*

        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_simple_encode() {
        let param = AnalyzedParam {
            name: "value".to_string(),
            ty: ResolvedType {
                kind: ResolvedTypeKind::Primitive(PrimitiveType::Long),
                alignment: 4,
                wire_size: 4,
            },
            direction: ParamDirection::In,
            is_retval: false,
            size_is: None,
            length_is: None,
            is_string: false,
        };

        let code = generate_param_encode(&param);
        let code_str = code.to_string();
        assert!(code_str.contains("ndr_encode"));
    }
}
