//! MIDL Abstract Syntax Tree
//!
//! This module defines the AST nodes for MIDL IDL files.

use crate::error::Span;

/// Root of an IDL file
#[derive(Debug, Clone)]
pub struct File {
    pub items: Vec<Item>,
}

/// Top-level items in an IDL file
#[derive(Debug, Clone)]
pub enum Item {
    /// import "filename"
    Import(Import),
    /// typedef
    Typedef(Typedef),
    /// struct definition
    Struct(Struct),
    /// enum definition
    Enum(Enum),
    /// union definition
    Union(Union),
    /// interface definition
    Interface(Interface),
    /// coclass definition (COM)
    Coclass(Coclass),
    /// library definition (COM)
    Library(Library),
    /// cpp_quote("...")
    CppQuote(String),
}

/// Import statement
#[derive(Debug, Clone)]
pub struct Import {
    pub filename: String,
    pub span: Option<Span>,
}

/// Typedef
#[derive(Debug, Clone)]
pub struct Typedef {
    pub attrs: Vec<Attribute>,
    pub base_type: Type,
    pub name: String,
    pub span: Option<Span>,
}

/// Type reference
#[derive(Debug, Clone)]
pub enum Type {
    /// Base types: void, boolean, byte, etc.
    Base(BaseType),
    /// Named type (typedef, struct, enum, interface)
    Named(String),
    /// Pointer type
    Pointer(PointerType),
    /// Array type
    Array(ArrayType),
    /// String type (with [string] attribute)
    String(StringType),
}

/// Base (primitive) types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseType {
    Void,
    Boolean,
    Byte,
    Char,
    WChar,
    Small,
    Short,
    Long,
    Hyper,
    Int,
    Int32,
    Int64,
    Float,
    Double,
    ErrorStatusT,
    HandleT,
    /// Unsigned small
    USmall,
    /// Unsigned short
    UShort,
    /// Unsigned long
    ULong,
    /// Unsigned hyper
    UHyper,
}

impl BaseType {
    pub fn is_unsigned(&self) -> bool {
        matches!(self, Self::USmall | Self::UShort | Self::ULong | Self::UHyper | Self::Byte)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Boolean => "boolean",
            Self::Byte => "byte",
            Self::Char => "char",
            Self::WChar => "wchar_t",
            Self::Small => "small",
            Self::Short => "short",
            Self::Long => "long",
            Self::Hyper => "hyper",
            Self::Int => "int",
            Self::Int32 => "__int32",
            Self::Int64 => "__int64",
            Self::Float => "float",
            Self::Double => "double",
            Self::ErrorStatusT => "error_status_t",
            Self::HandleT => "handle_t",
            Self::USmall => "unsigned small",
            Self::UShort => "unsigned short",
            Self::ULong => "unsigned long",
            Self::UHyper => "unsigned hyper",
        }
    }
}

/// Pointer type
#[derive(Debug, Clone)]
pub struct PointerType {
    pub pointee: Box<Type>,
    pub kind: PointerKind,
}

/// Pointer kind (determines wire representation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PointerKind {
    /// [ref] - non-null reference
    Ref,
    /// [unique] - nullable, no aliasing
    #[default]
    Unique,
    /// [ptr] - nullable, aliasing allowed
    Full,
}

/// Array type
#[derive(Debug, Clone)]
pub struct ArrayType {
    pub element: Box<Type>,
    pub size: ArraySize,
}

/// Array size specification
#[derive(Debug, Clone)]
pub enum ArraySize {
    /// Fixed size: [N]
    Fixed(usize),
    /// Conformant: [size_is(expr)]
    Conformant { size_is: String },
    /// Varying: [length_is(expr)] with fixed max
    Varying { max: usize, length_is: String },
    /// Conformant varying: [size_is(expr), length_is(expr)]
    ConformantVarying { size_is: String, length_is: String },
}

/// String type
#[derive(Debug, Clone)]
pub struct StringType {
    pub char_type: StringCharType,
    pub is_pointer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringCharType {
    Char,
    WChar,
}

/// Struct definition
#[derive(Debug, Clone)]
pub struct Struct {
    pub attrs: Vec<Attribute>,
    pub name: String,
    pub fields: Vec<Field>,
    pub span: Option<Span>,
}

/// Struct field
#[derive(Debug, Clone)]
pub struct Field {
    pub attrs: Vec<Attribute>,
    pub ty: Type,
    pub name: String,
    pub span: Option<Span>,
}

/// Enum definition
#[derive(Debug, Clone)]
pub struct Enum {
    pub attrs: Vec<Attribute>,
    pub name: String,
    pub variants: Vec<EnumVariant>,
    pub span: Option<Span>,
}

/// Enum variant
#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub value: Option<i64>,
    pub span: Option<Span>,
}

/// Union definition (discriminated union)
#[derive(Debug, Clone)]
pub struct Union {
    pub attrs: Vec<Attribute>,
    pub name: String,
    pub switch_type: Type,
    pub switch_is: Option<String>,
    pub arms: Vec<UnionArm>,
    pub span: Option<Span>,
}

/// Union arm (case)
#[derive(Debug, Clone)]
pub struct UnionArm {
    pub cases: Vec<UnionCase>,
    pub ty: Option<Type>,
    pub name: Option<String>,
    pub span: Option<Span>,
}

/// Union case label
#[derive(Debug, Clone)]
pub enum UnionCase {
    /// case N:
    Value(i64),
    /// default:
    Default,
}

/// Interface definition
#[derive(Debug, Clone)]
pub struct Interface {
    pub attrs: Vec<Attribute>,
    pub name: String,
    pub base: Option<String>,
    pub methods: Vec<Method>,
    pub span: Option<Span>,
}

/// Method definition
#[derive(Debug, Clone)]
pub struct Method {
    pub attrs: Vec<Attribute>,
    pub return_type: Type,
    pub name: String,
    pub params: Vec<Param>,
    pub span: Option<Span>,
}

/// Method parameter
#[derive(Debug, Clone)]
pub struct Param {
    pub attrs: Vec<Attribute>,
    pub ty: Type,
    pub name: String,
    pub span: Option<Span>,
}

/// Parameter direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParamDirection {
    In,
    Out,
    #[default]
    InOut,
}

/// Coclass definition (COM)
#[derive(Debug, Clone)]
pub struct Coclass {
    pub attrs: Vec<Attribute>,
    pub name: String,
    pub interfaces: Vec<CoclassInterface>,
    pub span: Option<Span>,
}

/// Interface reference in a coclass
#[derive(Debug, Clone)]
pub struct CoclassInterface {
    pub attrs: Vec<Attribute>,
    pub name: String,
    pub is_default: bool,
    pub is_source: bool,
}

/// Library definition (COM type library)
#[derive(Debug, Clone)]
pub struct Library {
    pub attrs: Vec<Attribute>,
    pub name: String,
    pub items: Vec<Item>,
    pub span: Option<Span>,
}

/// Attribute (in square brackets)
#[derive(Debug, Clone)]
pub enum Attribute {
    /// [uuid(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)]
    Uuid(String),
    /// [version(major.minor)]
    Version(u16, u16),
    /// [object] - COM interface
    Object,
    /// [local] - no marshaling
    Local,
    /// [in]
    In,
    /// [out]
    Out,
    /// [retval]
    Retval,
    /// [string]
    String,
    /// [ref]
    Ref,
    /// [unique]
    Unique,
    /// [ptr]
    Ptr,
    /// [size_is(expr)]
    SizeIs(String),
    /// [length_is(expr)]
    LengthIs(String),
    /// [max_is(expr)]
    MaxIs(String),
    /// [first_is(expr)]
    FirstIs(String),
    /// [last_is(expr)]
    LastIs(String),
    /// [switch_type(type)]
    SwitchType(String),
    /// [switch_is(expr)]
    SwitchIs(String),
    /// [case(value)]
    Case(i64),
    /// [default]
    Default,
    /// [pointer_default(kind)]
    PointerDefault(PointerKind),
    /// [v1_enum] - 32-bit enum
    V1Enum,
    /// [range(min, max)]
    Range(i64, i64),
    /// [endpoint("protocol:address")]
    Endpoint(Vec<String>),
    /// [helpstring("...")]
    HelpString(String),
    /// [id(n)] - dispatch ID
    Id(i32),
    /// [propget]
    PropGet,
    /// [propput]
    PropPut,
    /// [propputref]
    PropPutRef,
    /// [iid_is(param)]
    IidIs(String),
    /// [call_as(name)]
    CallAs(String),
    /// Unknown attribute
    Unknown(String, Option<String>),
}

impl Attribute {
    /// Check if this is a direction attribute
    pub fn is_direction(&self) -> bool {
        matches!(self, Attribute::In | Attribute::Out)
    }

    /// Check if this is a pointer attribute
    pub fn is_pointer_kind(&self) -> bool {
        matches!(self, Attribute::Ref | Attribute::Unique | Attribute::Ptr)
    }

    /// Get direction from attributes
    pub fn get_direction(attrs: &[Attribute]) -> ParamDirection {
        let has_in = attrs.iter().any(|a| matches!(a, Attribute::In));
        let has_out = attrs.iter().any(|a| matches!(a, Attribute::Out));
        match (has_in, has_out) {
            (true, false) => ParamDirection::In,
            (false, true) => ParamDirection::Out,
            _ => ParamDirection::InOut,
        }
    }

    /// Get pointer kind from attributes
    pub fn get_pointer_kind(attrs: &[Attribute]) -> Option<PointerKind> {
        for attr in attrs {
            match attr {
                Attribute::Ref => return Some(PointerKind::Ref),
                Attribute::Unique => return Some(PointerKind::Unique),
                Attribute::Ptr => return Some(PointerKind::Full),
                _ => {}
            }
        }
        None
    }

    /// Check if [string] attribute is present
    pub fn has_string(attrs: &[Attribute]) -> bool {
        attrs.iter().any(|a| matches!(a, Attribute::String))
    }

    /// Check if [retval] attribute is present
    pub fn has_retval(attrs: &[Attribute]) -> bool {
        attrs.iter().any(|a| matches!(a, Attribute::Retval))
    }

    /// Get size_is expression if present
    pub fn get_size_is(attrs: &[Attribute]) -> Option<&str> {
        for attr in attrs {
            if let Attribute::SizeIs(expr) = attr {
                return Some(expr);
            }
        }
        None
    }

    /// Get length_is expression if present
    pub fn get_length_is(attrs: &[Attribute]) -> Option<&str> {
        for attr in attrs {
            if let Attribute::LengthIs(expr) = attr {
                return Some(expr);
            }
        }
        None
    }
}

impl File {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }
}

impl Default for File {
    fn default() -> Self {
        Self::new()
    }
}
