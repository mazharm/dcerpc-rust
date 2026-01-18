//! Semantic Analysis
//!
//! Performs type resolution, validation, and builds a symbol table for code generation.

use crate::ast::*;
use crate::error::Result;
use std::collections::HashMap;

// Re-export ParamDirection for use in codegen
pub use crate::ast::ParamDirection;

/// Analyzed file with resolved types
#[derive(Debug)]
pub struct AnalyzedFile {
    pub interfaces: Vec<AnalyzedInterface>,
    pub types: Vec<AnalyzedType>,
    pub type_map: HashMap<String, TypeInfo>,
}

/// Analyzed interface
#[derive(Debug)]
pub struct AnalyzedInterface {
    pub name: String,
    pub uuid: Option<String>,
    pub version: (u16, u16),
    pub is_object: bool,
    pub is_local: bool,
    pub base: Option<String>,
    pub pointer_default: PointerKind,
    pub methods: Vec<AnalyzedMethod>,
}

/// Analyzed method
#[derive(Debug)]
pub struct AnalyzedMethod {
    pub name: String,
    pub opnum: u16,
    pub return_type: ResolvedType,
    pub params: Vec<AnalyzedParam>,
}

/// Analyzed parameter
#[derive(Debug)]
pub struct AnalyzedParam {
    pub name: String,
    pub ty: ResolvedType,
    pub direction: ParamDirection,
    pub is_retval: bool,
    pub size_is: Option<String>,
    pub length_is: Option<String>,
    pub is_string: bool,
}

/// Analyzed type definition
#[derive(Debug)]
pub enum AnalyzedType {
    Typedef(AnalyzedTypedef),
    Struct(AnalyzedStruct),
    Enum(AnalyzedEnum),
    Union(AnalyzedUnion),
}

/// Analyzed typedef
#[derive(Debug)]
pub struct AnalyzedTypedef {
    pub name: String,
    pub target: ResolvedType,
}

/// Analyzed struct
#[derive(Debug)]
pub struct AnalyzedStruct {
    pub name: String,
    pub fields: Vec<AnalyzedField>,
    pub alignment: usize,
    pub size: usize,
    pub has_conformant_array: bool,
}

/// Analyzed field
#[derive(Debug)]
pub struct AnalyzedField {
    pub name: String,
    pub ty: ResolvedType,
    pub offset: usize,
    pub size_is: Option<String>,
    pub length_is: Option<String>,
    pub is_string: bool,
}

/// Analyzed enum
#[derive(Debug)]
pub struct AnalyzedEnum {
    pub name: String,
    pub variants: Vec<(String, i64)>,
    pub is_v1_enum: bool, // 32-bit
}

/// Analyzed union
#[derive(Debug)]
pub struct AnalyzedUnion {
    pub name: String,
    pub switch_type: ResolvedType,
    pub arms: Vec<AnalyzedUnionArm>,
}

/// Analyzed union arm
#[derive(Debug)]
pub struct AnalyzedUnionArm {
    pub discriminant: UnionCase,
    pub ty: Option<ResolvedType>,
    pub name: Option<String>,
}

/// Resolved type with full information
#[derive(Debug, Clone)]
pub struct ResolvedType {
    pub kind: ResolvedTypeKind,
    pub alignment: usize,
    pub wire_size: usize,
}

/// Resolved type kinds
#[derive(Debug, Clone)]
pub enum ResolvedTypeKind {
    /// Void type
    Void,
    /// Primitive type
    Primitive(PrimitiveType),
    /// Pointer to another type
    Pointer {
        pointee: Box<ResolvedType>,
        kind: PointerKind,
    },
    /// Fixed-size array
    FixedArray {
        element: Box<ResolvedType>,
        size: usize,
    },
    /// Conformant array
    ConformantArray {
        element: Box<ResolvedType>,
        size_is: String,
    },
    /// Varying array
    VaryingArray {
        element: Box<ResolvedType>,
        max: usize,
        length_is: String,
    },
    /// Conformant varying array
    ConformantVaryingArray {
        element: Box<ResolvedType>,
        size_is: String,
        length_is: String,
    },
    /// String type
    String(StringCharType),
    /// Named type (struct, enum, union, typedef)
    Named(String),
}

/// Primitive types with NDR info
#[derive(Debug, Clone, Copy)]
pub enum PrimitiveType {
    Boolean,
    Byte,
    Char,
    WChar,
    Small,
    USmall,
    Short,
    UShort,
    Long,
    ULong,
    Hyper,
    UHyper,
    Float,
    Double,
    ErrorStatusT,
    HandleT,
}

impl PrimitiveType {
    pub fn alignment(&self) -> usize {
        match self {
            Self::Boolean | Self::Byte | Self::Char | Self::Small | Self::USmall => 1,
            Self::WChar | Self::Short | Self::UShort => 2,
            Self::Long | Self::ULong | Self::Float | Self::ErrorStatusT | Self::HandleT => 4,
            Self::Hyper | Self::UHyper | Self::Double => 8,
        }
    }

    pub fn size(&self) -> usize {
        self.alignment()
    }
}

/// Type information for the symbol table
#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub resolved: ResolvedType,
    pub is_builtin: bool,
}

/// Analyzer state
struct Analyzer {
    types: HashMap<String, TypeInfo>,
}

impl Analyzer {
    fn new() -> Self {
        let mut types = HashMap::new();

        // Register built-in types
        let builtins = [
            ("boolean", PrimitiveType::Boolean),
            ("byte", PrimitiveType::Byte),
            ("char", PrimitiveType::Char),
            ("wchar_t", PrimitiveType::WChar),
            ("small", PrimitiveType::Small),
            ("short", PrimitiveType::Short),
            ("long", PrimitiveType::Long),
            ("hyper", PrimitiveType::Hyper),
            ("int", PrimitiveType::Long),
            ("__int32", PrimitiveType::Long),
            ("__int64", PrimitiveType::Hyper),
            ("float", PrimitiveType::Float),
            ("double", PrimitiveType::Double),
            ("error_status_t", PrimitiveType::ErrorStatusT),
            ("handle_t", PrimitiveType::HandleT),
            ("BYTE", PrimitiveType::Byte),
            ("CHAR", PrimitiveType::Char),
            ("WCHAR", PrimitiveType::WChar),
            ("SHORT", PrimitiveType::Short),
            ("LONG", PrimitiveType::Long),
            ("DWORD", PrimitiveType::ULong),
            ("ULONG", PrimitiveType::ULong),
            ("USHORT", PrimitiveType::UShort),
            ("INT", PrimitiveType::Long),
            ("UINT", PrimitiveType::ULong),
            ("BOOL", PrimitiveType::Long),
            ("HRESULT", PrimitiveType::Long),
        ];

        for (name, prim) in builtins {
            types.insert(name.to_string(), TypeInfo {
                resolved: ResolvedType {
                    kind: ResolvedTypeKind::Primitive(prim),
                    alignment: prim.alignment(),
                    wire_size: prim.size(),
                },
                is_builtin: true,
            });
        }

        Self { types }
    }

    fn analyze(&mut self, file: &File) -> Result<AnalyzedFile> {
        let mut interfaces = Vec::new();
        let mut analyzed_types = Vec::new();

        // First pass: register all type names
        for item in &file.items {
            match item {
                Item::Typedef(td) => {
                    self.register_type_name(&td.name)?;
                }
                Item::Struct(s) => {
                    self.register_type_name(&s.name)?;
                }
                Item::Enum(e) => {
                    self.register_type_name(&e.name)?;
                }
                Item::Union(u) => {
                    self.register_type_name(&u.name)?;
                }
                _ => {}
            }
        }

        // Second pass: analyze all definitions
        for item in &file.items {
            match item {
                Item::Interface(iface) => {
                    interfaces.push(self.analyze_interface(iface)?);
                }
                Item::Typedef(td) => {
                    analyzed_types.push(AnalyzedType::Typedef(self.analyze_typedef(td)?));
                }
                Item::Struct(s) => {
                    analyzed_types.push(AnalyzedType::Struct(self.analyze_struct(s)?));
                }
                Item::Enum(e) => {
                    analyzed_types.push(AnalyzedType::Enum(self.analyze_enum(e)?));
                }
                Item::Union(u) => {
                    analyzed_types.push(AnalyzedType::Union(self.analyze_union(u)?));
                }
                _ => {}
            }
        }

        Ok(AnalyzedFile {
            interfaces,
            types: analyzed_types,
            type_map: self.types.clone(),
        })
    }

    fn register_type_name(&mut self, name: &str) -> Result<()> {
        if self.types.contains_key(name) && self.types[name].is_builtin {
            return Ok(()); // Allow overriding builtins
        }
        // Placeholder entry - will be filled during analysis
        self.types.insert(name.to_string(), TypeInfo {
            resolved: ResolvedType {
                kind: ResolvedTypeKind::Named(name.to_string()),
                alignment: 1,
                wire_size: 0,
            },
            is_builtin: false,
        });
        Ok(())
    }

    fn analyze_interface(&mut self, iface: &Interface) -> Result<AnalyzedInterface> {
        let mut uuid = None;
        let mut version = (1, 0);
        let mut is_object = false;
        let mut is_local = false;
        let mut pointer_default = PointerKind::Unique;

        for attr in &iface.attrs {
            match attr {
                Attribute::Uuid(u) => uuid = Some(u.clone()),
                Attribute::Version(major, minor) => version = (*major, *minor),
                Attribute::Object => is_object = true,
                Attribute::Local => is_local = true,
                Attribute::PointerDefault(k) => pointer_default = *k,
                _ => {}
            }
        }

        let methods: Result<Vec<_>> = iface.methods.iter()
            .enumerate()
            .map(|(i, m)| self.analyze_method(m, i as u16, pointer_default))
            .collect();

        Ok(AnalyzedInterface {
            name: iface.name.clone(),
            uuid,
            version,
            is_object,
            is_local,
            base: iface.base.clone(),
            pointer_default,
            methods: methods?,
        })
    }

    fn analyze_method(&mut self, method: &Method, opnum: u16, default_ptr: PointerKind) -> Result<AnalyzedMethod> {
        let return_type = self.resolve_type(&method.return_type, &[], default_ptr)?;

        let params: Result<Vec<_>> = method.params.iter()
            .map(|p| self.analyze_param(p, default_ptr))
            .collect();

        Ok(AnalyzedMethod {
            name: method.name.clone(),
            opnum,
            return_type,
            params: params?,
        })
    }

    fn analyze_param(&mut self, param: &Param, default_ptr: PointerKind) -> Result<AnalyzedParam> {
        let direction = Attribute::get_direction(&param.attrs);
        let is_retval = Attribute::has_retval(&param.attrs);
        let is_string = Attribute::has_string(&param.attrs);
        let size_is = Attribute::get_size_is(&param.attrs).map(|s| s.to_string());
        let length_is = Attribute::get_length_is(&param.attrs).map(|s| s.to_string());

        let ty = self.resolve_type(&param.ty, &param.attrs, default_ptr)?;

        Ok(AnalyzedParam {
            name: param.name.clone(),
            ty,
            direction,
            is_retval,
            size_is,
            length_is,
            is_string,
        })
    }

    fn analyze_typedef(&mut self, td: &Typedef) -> Result<AnalyzedTypedef> {
        let target = self.resolve_type(&td.base_type, &td.attrs, PointerKind::Unique)?;

        // Update the type map
        self.types.insert(td.name.clone(), TypeInfo {
            resolved: target.clone(),
            is_builtin: false,
        });

        Ok(AnalyzedTypedef {
            name: td.name.clone(),
            target,
        })
    }

    fn analyze_struct(&mut self, s: &Struct) -> Result<AnalyzedStruct> {
        let mut fields = Vec::new();
        let mut offset = 0;
        let mut max_align = 1;
        let mut has_conformant = false;

        for field in &s.fields {
            let is_string = Attribute::has_string(&field.attrs);
            let size_is = Attribute::get_size_is(&field.attrs).map(|s| s.to_string());
            let length_is = Attribute::get_length_is(&field.attrs).map(|s| s.to_string());

            let ty = self.resolve_type(&field.ty, &field.attrs, PointerKind::Unique)?;

            // Check for conformant array
            if matches!(ty.kind, ResolvedTypeKind::ConformantArray { .. } |
                                  ResolvedTypeKind::ConformantVaryingArray { .. }) {
                has_conformant = true;
            }

            // Apply alignment
            let align = ty.alignment;
            max_align = max_align.max(align);
            let padding = (align - (offset % align)) % align;
            offset += padding;

            fields.push(AnalyzedField {
                name: field.name.clone(),
                ty: ty.clone(),
                offset,
                size_is,
                length_is,
                is_string,
            });

            offset += ty.wire_size;
        }

        // Final alignment
        let padding = (max_align - (offset % max_align)) % max_align;
        let size = offset + padding;

        // Update type map
        self.types.insert(s.name.clone(), TypeInfo {
            resolved: ResolvedType {
                kind: ResolvedTypeKind::Named(s.name.clone()),
                alignment: max_align,
                wire_size: size,
            },
            is_builtin: false,
        });

        Ok(AnalyzedStruct {
            name: s.name.clone(),
            fields,
            alignment: max_align,
            size,
            has_conformant_array: has_conformant,
        })
    }

    fn analyze_enum(&mut self, e: &Enum) -> Result<AnalyzedEnum> {
        let is_v1_enum = e.attrs.iter().any(|a| matches!(a, Attribute::V1Enum));
        let size = if is_v1_enum { 4 } else { 2 };

        let variants: Vec<_> = e.variants.iter()
            .map(|v| (v.name.clone(), v.value.unwrap_or(0)))
            .collect();

        // Update type map
        self.types.insert(e.name.clone(), TypeInfo {
            resolved: ResolvedType {
                kind: ResolvedTypeKind::Named(e.name.clone()),
                alignment: size,
                wire_size: size,
            },
            is_builtin: false,
        });

        Ok(AnalyzedEnum {
            name: e.name.clone(),
            variants,
            is_v1_enum,
        })
    }

    fn analyze_union(&mut self, u: &Union) -> Result<AnalyzedUnion> {
        let switch_type = self.resolve_type(&u.switch_type, &[], PointerKind::Unique)?;

        let arms: Result<Vec<_>> = u.arms.iter().flat_map(|arm| {
            arm.cases.iter().map(|case| {
                let ty = arm.ty.as_ref()
                    .map(|t| self.resolve_type(t, &[], PointerKind::Unique))
                    .transpose();
                ty.map(|resolved| AnalyzedUnionArm {
                    discriminant: case.clone(),
                    ty: resolved,
                    name: arm.name.clone(),
                })
            })
        }).collect();

        // Update type map - union size is discriminant + max arm size
        self.types.insert(u.name.clone(), TypeInfo {
            resolved: ResolvedType {
                kind: ResolvedTypeKind::Named(u.name.clone()),
                alignment: 4,
                wire_size: 0, // Variable
            },
            is_builtin: false,
        });

        Ok(AnalyzedUnion {
            name: u.name.clone(),
            switch_type,
            arms: arms?,
        })
    }

    fn resolve_type(&self, ty: &Type, attrs: &[Attribute], default_ptr: PointerKind) -> Result<ResolvedType> {
        let is_string = Attribute::has_string(attrs);
        let size_is = Attribute::get_size_is(attrs);
        let _length_is = Attribute::get_length_is(attrs);
        let ptr_kind = Attribute::get_pointer_kind(attrs).unwrap_or(default_ptr);

        match ty {
            Type::Base(base) => {
                let prim = match base {
                    BaseType::Void => return Ok(ResolvedType {
                        kind: ResolvedTypeKind::Void,
                        alignment: 1,
                        wire_size: 0,
                    }),
                    BaseType::Boolean => PrimitiveType::Boolean,
                    BaseType::Byte => PrimitiveType::Byte,
                    BaseType::Char => PrimitiveType::Char,
                    BaseType::WChar => PrimitiveType::WChar,
                    BaseType::Small => PrimitiveType::Small,
                    BaseType::Short => PrimitiveType::Short,
                    BaseType::Long | BaseType::Int | BaseType::Int32 => PrimitiveType::Long,
                    BaseType::Hyper | BaseType::Int64 => PrimitiveType::Hyper,
                    BaseType::Float => PrimitiveType::Float,
                    BaseType::Double => PrimitiveType::Double,
                    BaseType::ErrorStatusT => PrimitiveType::ErrorStatusT,
                    BaseType::HandleT => PrimitiveType::HandleT,
                    BaseType::USmall => PrimitiveType::USmall,
                    BaseType::UShort => PrimitiveType::UShort,
                    BaseType::ULong => PrimitiveType::ULong,
                    BaseType::UHyper => PrimitiveType::UHyper,
                };

                Ok(ResolvedType {
                    kind: ResolvedTypeKind::Primitive(prim),
                    alignment: prim.alignment(),
                    wire_size: prim.size(),
                })
            }

            Type::Named(name) => {
                if let Some(info) = self.types.get(name) {
                    Ok(info.resolved.clone())
                } else {
                    // Forward reference - return placeholder
                    Ok(ResolvedType {
                        kind: ResolvedTypeKind::Named(name.clone()),
                        alignment: 1,
                        wire_size: 0,
                    })
                }
            }

            Type::Pointer(ptr) => {
                let pointee = self.resolve_type(&ptr.pointee, &[], default_ptr)?;

                // Check for string
                if is_string {
                    let char_type = match &pointee.kind {
                        ResolvedTypeKind::Primitive(PrimitiveType::Char) => StringCharType::Char,
                        ResolvedTypeKind::Primitive(PrimitiveType::WChar) => StringCharType::WChar,
                        _ => StringCharType::Char,
                    };
                    return Ok(ResolvedType {
                        kind: ResolvedTypeKind::String(char_type),
                        alignment: 4,
                        wire_size: 0, // Variable
                    });
                }

                Ok(ResolvedType {
                    kind: ResolvedTypeKind::Pointer {
                        pointee: Box::new(pointee),
                        kind: ptr_kind,
                    },
                    alignment: 4, // Pointer referent ID
                    wire_size: 4, // Just the referent ID
                })
            }

            Type::Array(arr) => {
                let element = self.resolve_type(&arr.element, &[], default_ptr)?;

                let kind = match &arr.size {
                    ArraySize::Fixed(n) => {
                        let size = element.wire_size * n;
                        return Ok(ResolvedType {
                            kind: ResolvedTypeKind::FixedArray {
                                element: Box::new(element.clone()),
                                size: *n,
                            },
                            alignment: element.alignment,
                            wire_size: size,
                        });
                    }
                    ArraySize::Conformant { size_is: s } => {
                        let s = if s.is_empty() {
                            size_is.unwrap_or("").to_string()
                        } else {
                            s.clone()
                        };
                        ResolvedTypeKind::ConformantArray {
                            element: Box::new(element.clone()),
                            size_is: s,
                        }
                    }
                    ArraySize::Varying { max, length_is: l } => {
                        ResolvedTypeKind::VaryingArray {
                            element: Box::new(element.clone()),
                            max: *max,
                            length_is: l.clone(),
                        }
                    }
                    ArraySize::ConformantVarying { size_is: s, length_is: l } => {
                        ResolvedTypeKind::ConformantVaryingArray {
                            element: Box::new(element.clone()),
                            size_is: s.clone(),
                            length_is: l.clone(),
                        }
                    }
                };

                Ok(ResolvedType {
                    kind,
                    alignment: 4.max(element.alignment), // Conformance data aligns to 4
                    wire_size: 0, // Variable
                })
            }

            Type::String(s) => {
                Ok(ResolvedType {
                    kind: ResolvedTypeKind::String(s.char_type),
                    alignment: 4,
                    wire_size: 0,
                })
            }
        }
    }
}

/// Analyze a parsed IDL file
pub fn analyze(file: &File) -> Result<AnalyzedFile> {
    let mut analyzer = Analyzer::new();
    analyzer.analyze(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn test_analyze_interface() {
        let input = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface ICalculator {
                long Add([in] long a, [in] long b);
            }
        "#;

        let file = parser::parse(input).unwrap();
        let analyzed = analyze(&file).unwrap();

        assert_eq!(analyzed.interfaces.len(), 1);
        let iface = &analyzed.interfaces[0];
        assert_eq!(iface.name, "ICalculator");
        assert_eq!(iface.methods.len(), 1);
        assert_eq!(iface.methods[0].params.len(), 2);
    }

    #[test]
    fn test_resolve_primitive() {
        let input = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface ITest {
                long GetLong();
                hyper GetHyper();
                double GetDouble();
            }
        "#;

        let file = parser::parse(input).unwrap();
        let analyzed = analyze(&file).unwrap();

        let iface = &analyzed.interfaces[0];
        assert!(matches!(iface.methods[0].return_type.kind,
            ResolvedTypeKind::Primitive(PrimitiveType::Long)));
        assert!(matches!(iface.methods[1].return_type.kind,
            ResolvedTypeKind::Primitive(PrimitiveType::Hyper)));
        assert!(matches!(iface.methods[2].return_type.kind,
            ResolvedTypeKind::Primitive(PrimitiveType::Double)));
    }
}
