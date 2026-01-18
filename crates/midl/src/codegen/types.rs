//! Type definition code generation
//!
//! Generates Rust struct, enum, and union definitions from MIDL types.

use crate::error::Result;
use crate::semantic::{AnalyzedType, AnalyzedStruct, AnalyzedEnum, AnalyzedUnion, AnalyzedTypedef, ResolvedTypeKind, PrimitiveType};
use proc_macro2::TokenStream;
use quote::{quote, format_ident};

/// Generate code for a type definition
pub fn generate_type(ty: &AnalyzedType) -> Result<TokenStream> {
    match ty {
        AnalyzedType::Typedef(td) => generate_typedef(td),
        AnalyzedType::Struct(s) => generate_struct(s),
        AnalyzedType::Enum(e) => generate_enum(e),
        AnalyzedType::Union(u) => generate_union(u),
    }
}

/// Generate typedef
fn generate_typedef(td: &AnalyzedTypedef) -> Result<TokenStream> {
    let name = format_ident!("{}", &td.name);
    let target = type_to_rust(&td.target.kind);

    Ok(quote! {
        pub type #name = #target;
    })
}

/// Generate struct definition with NdrEncode/NdrDecode
fn generate_struct(s: &AnalyzedStruct) -> Result<TokenStream> {
    let name = format_ident!("{}", &s.name);

    // Generate fields
    let fields: Vec<_> = s.fields.iter().map(|f| {
        let field_name = format_ident!("{}", &f.name);
        let field_type = type_to_rust(&f.ty.kind);
        quote! { pub #field_name: #field_type }
    }).collect();

    // Generate NdrEncode implementation
    let encode_fields: Vec<_> = s.fields.iter().map(|f| {
        let field_name = format_ident!("{}", &f.name);
        quote! {
            self.#field_name.ndr_encode(buf, ctx, position)?;
        }
    }).collect();

    // Generate NdrDecode implementation
    let decode_fields: Vec<_> = s.fields.iter().map(|f| {
        let field_name = format_ident!("{}", &f.name);
        let field_type = type_to_rust(&f.ty.kind);
        quote! {
            #field_name: <#field_type as NdrDecode>::ndr_decode(buf, ctx, position)?
        }
    }).collect();

    // Calculate size
    let field_sizes: Vec<_> = s.fields.iter().map(|f| {
        let field_name = format_ident!("{}", &f.name);
        quote! { self.#field_name.ndr_size() }
    }).collect();

    let alignment = s.alignment;

    Ok(quote! {
        #[derive(Debug, Clone, Default)]
        pub struct #name {
            #(#fields,)*
        }

        impl NdrEncode for #name {
            fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> NdrResult<()> {
                // Align to struct alignment
                let padding = NdrContext::align_padding(*position, #alignment);
                for _ in 0..padding {
                    buf.put_u8(0);
                }
                *position += padding;

                #(#encode_fields)*
                Ok(())
            }

            fn ndr_align() -> usize {
                #alignment
            }

            fn ndr_size(&self) -> usize {
                #(#field_sizes)+*
            }
        }

        impl NdrDecode for #name {
            fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> NdrResult<Self> {
                // Align to struct alignment
                let padding = NdrContext::align_padding(*position, #alignment);
                buf.advance(padding);
                *position += padding;

                Ok(Self {
                    #(#decode_fields,)*
                })
            }

            fn ndr_align() -> usize {
                #alignment
            }
        }
    })
}

/// Generate enum definition
fn generate_enum(e: &AnalyzedEnum) -> Result<TokenStream> {
    let name = format_ident!("{}", &e.name);

    // Generate variants
    let variants: Vec<_> = e.variants.iter().map(|(var_name, value)| {
        let var_ident = format_ident!("{}", var_name);
        let val = *value as i32;
        quote! { #var_ident = #val }
    }).collect();

    // Determine the representation type
    let repr_type = if e.is_v1_enum {
        quote! { i32 }
    } else {
        quote! { i16 }
    };

    let repr_attr = if e.is_v1_enum {
        quote! { #[repr(i32)] }
    } else {
        quote! { #[repr(i16)] }
    };

    // Generate from_value method
    let from_cases: Vec<_> = e.variants.iter().map(|(var_name, value)| {
        let var_ident = format_ident!("{}", var_name);
        let val = *value as i32;
        quote! { #val => Some(Self::#var_ident) }
    }).collect();

    let first_variant = e.variants.first().map(|(name, _)| format_ident!("{}", name));

    let alignment = if e.is_v1_enum { 4usize } else { 2usize };
    let size = alignment;

    Ok(quote! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #repr_attr
        pub enum #name {
            #(#variants,)*
        }

        impl #name {
            pub fn from_value(v: #repr_type) -> Option<Self> {
                match v as i32 {
                    #(#from_cases,)*
                    _ => None,
                }
            }
        }

        impl Default for #name {
            fn default() -> Self {
                Self::#first_variant
            }
        }

        impl NdrEncode for #name {
            fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> NdrResult<()> {
                let value = *self as #repr_type;
                value.ndr_encode(buf, ctx, position)
            }

            fn ndr_align() -> usize {
                #alignment
            }

            fn ndr_size(&self) -> usize {
                #size
            }
        }

        impl NdrDecode for #name {
            fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> NdrResult<Self> {
                let value = <#repr_type as NdrDecode>::ndr_decode(buf, ctx, position)?;
                Self::from_value(value).ok_or_else(|| {
                    midl_ndr::NdrError::InvalidEnumValue(value as i32)
                })
            }

            fn ndr_align() -> usize {
                #alignment
            }
        }
    })
}

/// Generate union definition
fn generate_union(u: &AnalyzedUnion) -> Result<TokenStream> {
    let name = format_ident!("{}", &u.name);
    let switch_type = type_to_rust(&u.switch_type.kind);

    // Generate variant names and types
    let variants: Vec<_> = u.arms.iter().filter_map(|arm| {
        match &arm.discriminant {
            crate::ast::UnionCase::Value(v) => {
                let var_name = arm.name.as_ref()
                    .map(|n| format_ident!("{}", n))
                    .unwrap_or_else(|| format_ident!("Case{}", *v as u64));
                let var_type = arm.ty.as_ref().map(|t| type_to_rust(&t.kind));
                Some((var_name, var_type, *v))
            }
            crate::ast::UnionCase::Default => {
                let var_name = arm.name.as_ref()
                    .map(|n| format_ident!("{}", n))
                    .unwrap_or_else(|| format_ident!("Default"));
                let var_type = arm.ty.as_ref().map(|t| type_to_rust(&t.kind));
                Some((var_name, var_type, i64::MIN)) // Special marker for default
            }
        }
    }).collect();

    let enum_variants: Vec<_> = variants.iter().map(|(name, ty, _)| {
        match ty {
            Some(t) => quote! { #name(#t) },
            None => quote! { #name },
        }
    }).collect();

    // Generate encode match arms
    let encode_arms: Vec<_> = variants.iter().map(|(name, ty, value)| {
        let disc_value = if *value == i64::MIN {
            quote! { _ }
        } else {
            let v = *value as i32;
            quote! { #v }
        };
        match ty {
            Some(_) => quote! {
                Self::#name(val) => {
                    (#disc_value as #switch_type).ndr_encode(buf, ctx, position)?;
                    val.ndr_encode(buf, ctx, position)?;
                }
            },
            None => quote! {
                Self::#name => {
                    (#disc_value as #switch_type).ndr_encode(buf, ctx, position)?;
                }
            },
        }
    }).collect();

    // Generate decode match arms
    let decode_arms: Vec<_> = variants.iter().filter(|(_, _, v)| *v != i64::MIN).map(|(name, ty, value)| {
        let v = *value as i32;
        match ty {
            Some(t) => quote! {
                #v => Ok(Self::#name(<#t as NdrDecode>::ndr_decode(buf, ctx, position)?))
            },
            None => quote! {
                #v => Ok(Self::#name)
            },
        }
    }).collect();

    let default_arm = variants.iter().find(|(_, _, v)| *v == i64::MIN).map(|(name, ty, _)| {
        match ty {
            Some(t) => quote! {
                _ => Ok(Self::#name(<#t as NdrDecode>::ndr_decode(buf, ctx, position)?))
            },
            None => quote! {
                _ => Ok(Self::#name)
            },
        }
    }).unwrap_or_else(|| quote! {
        v => Err(midl_ndr::NdrError::InvalidDiscriminant(v))
    });

    let first_variant = variants.first().map(|(name, ty, _)| {
        match ty {
            Some(_) => quote! { Self::#name(Default::default()) },
            None => quote! { Self::#name },
        }
    }).unwrap_or_else(|| quote! { panic!("empty union") });

    Ok(quote! {
        #[derive(Debug, Clone)]
        pub enum #name {
            #(#enum_variants,)*
        }

        impl Default for #name {
            fn default() -> Self {
                #first_variant
            }
        }

        impl NdrEncode for #name {
            fn ndr_encode<B: BufMut>(&self, buf: &mut B, ctx: &NdrContext, position: &mut usize) -> NdrResult<()> {
                match self {
                    #(#encode_arms)*
                }
                Ok(())
            }

            fn ndr_align() -> usize {
                4
            }

            fn ndr_size(&self) -> usize {
                4 // Discriminant; arm size is variable
            }
        }

        impl NdrDecode for #name {
            fn ndr_decode<B: Buf>(buf: &mut B, ctx: &NdrContext, position: &mut usize) -> NdrResult<Self> {
                let discriminant = <#switch_type as NdrDecode>::ndr_decode(buf, ctx, position)? as i32;
                match discriminant {
                    #(#decode_arms,)*
                    #default_arm
                }
            }

            fn ndr_align() -> usize {
                4
            }
        }
    })
}

/// Convert a resolved type to Rust tokens
pub fn type_to_rust(kind: &ResolvedTypeKind) -> TokenStream {
    match kind {
        ResolvedTypeKind::Void => quote! { () },

        ResolvedTypeKind::Primitive(prim) => match prim {
            PrimitiveType::Boolean => quote! { bool },
            PrimitiveType::Byte => quote! { u8 },
            PrimitiveType::Char => quote! { u8 },
            PrimitiveType::WChar => quote! { u16 },
            PrimitiveType::Small => quote! { i8 },
            PrimitiveType::USmall => quote! { u8 },
            PrimitiveType::Short => quote! { i16 },
            PrimitiveType::UShort => quote! { u16 },
            PrimitiveType::Long => quote! { i32 },
            PrimitiveType::ULong => quote! { u32 },
            PrimitiveType::Hyper => quote! { i64 },
            PrimitiveType::UHyper => quote! { u64 },
            PrimitiveType::Float => quote! { f32 },
            PrimitiveType::Double => quote! { f64 },
            PrimitiveType::ErrorStatusT => quote! { u32 },
            PrimitiveType::HandleT => quote! { u32 },
        },

        ResolvedTypeKind::Pointer { pointee, kind } => {
            let inner = type_to_rust(&pointee.kind);
            match kind {
                crate::ast::PointerKind::Ref => quote! { midl_ndr::RefPtr<#inner> },
                crate::ast::PointerKind::Unique => quote! { midl_ndr::UniquePtr<#inner> },
                crate::ast::PointerKind::Full => quote! { midl_ndr::FullPtr<#inner> },
            }
        }

        ResolvedTypeKind::FixedArray { element, size } => {
            let elem = type_to_rust(&element.kind);
            quote! { [#elem; #size] }
        }

        ResolvedTypeKind::ConformantArray { element, .. } => {
            let elem = type_to_rust(&element.kind);
            quote! { midl_ndr::ConformantArray<#elem> }
        }

        ResolvedTypeKind::VaryingArray { element, max, .. } => {
            let elem = type_to_rust(&element.kind);
            quote! { midl_ndr::VaryingArray<#elem, #max> }
        }

        ResolvedTypeKind::ConformantVaryingArray { element, .. } => {
            let elem = type_to_rust(&element.kind);
            quote! { midl_ndr::ConformantVaryingArray<#elem> }
        }

        ResolvedTypeKind::String(char_type) => match char_type {
            crate::ast::StringCharType::Char => quote! { midl_ndr::NdrString },
            crate::ast::StringCharType::WChar => quote! { midl_ndr::NdrWString },
        },

        ResolvedTypeKind::Named(name) => {
            let ident = format_ident!("{}", name);
            quote! { #ident }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_to_rust_primitives() {
        assert_eq!(
            type_to_rust(&ResolvedTypeKind::Primitive(PrimitiveType::Long)).to_string(),
            "i32"
        );
        assert_eq!(
            type_to_rust(&ResolvedTypeKind::Primitive(PrimitiveType::Boolean)).to_string(),
            "bool"
        );
    }
}
