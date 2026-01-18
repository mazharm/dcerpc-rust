//! NDR Layout Calculations
//!
//! Computes NDR wire sizes, alignments, and offsets for types.

use crate::semantic::{ResolvedType, ResolvedTypeKind, PrimitiveType};

/// NDR layout information for a type
#[derive(Debug, Clone)]
pub struct NdrLayout {
    /// Alignment requirement in bytes
    pub alignment: usize,
    /// Size in bytes (0 for variable-size types)
    pub size: usize,
    /// Whether this type has variable size
    pub is_variable: bool,
    /// Whether this has conformant data (size at struct start, data at end)
    pub has_conformant: bool,
}

impl NdrLayout {
    /// Get the layout for a resolved type
    pub fn for_type(ty: &ResolvedType) -> Self {
        match &ty.kind {
            ResolvedTypeKind::Void => Self {
                alignment: 1,
                size: 0,
                is_variable: false,
                has_conformant: false,
            },

            ResolvedTypeKind::Primitive(prim) => {
                let (alignment, size) = primitive_layout(*prim);
                Self {
                    alignment,
                    size,
                    is_variable: false,
                    has_conformant: false,
                }
            }

            ResolvedTypeKind::Pointer { pointee: _, kind } => {
                // Pointers are 4-byte referent IDs plus the data if non-null
                // For ref pointers, no referent ID is transmitted
                match kind {
                    crate::ast::PointerKind::Ref => Self {
                        alignment: 4, // Still aligns like a pointer
                        size: 0, // But no referent ID transmitted
                        is_variable: true,
                        has_conformant: false,
                    },
                    _ => Self {
                        alignment: 4,
                        size: 4, // Just the referent ID; pointee is variable
                        is_variable: true,
                        has_conformant: false,
                    },
                }
            }

            ResolvedTypeKind::FixedArray { element, size: count } => {
                let elem_layout = Self::for_type(element);
                Self {
                    alignment: elem_layout.alignment,
                    size: elem_layout.size * count,
                    is_variable: false,
                    has_conformant: false,
                }
            }

            ResolvedTypeKind::ConformantArray { element, .. } => {
                let elem_layout = Self::for_type(element);
                Self {
                    alignment: 4.max(elem_layout.alignment), // max_count aligns to 4
                    size: 0, // Variable
                    is_variable: true,
                    has_conformant: true,
                }
            }

            ResolvedTypeKind::VaryingArray { element, max, .. } => {
                let elem_layout = Self::for_type(element);
                Self {
                    alignment: 4.max(elem_layout.alignment),
                    size: 8 + elem_layout.size * max, // offset + actual_count + data
                    is_variable: true, // actual_count varies
                    has_conformant: false,
                }
            }

            ResolvedTypeKind::ConformantVaryingArray { element, .. } => {
                let elem_layout = Self::for_type(element);
                Self {
                    alignment: 4.max(elem_layout.alignment),
                    size: 0, // Variable
                    is_variable: true,
                    has_conformant: true,
                }
            }

            ResolvedTypeKind::String(char_type) => {
                let _char_size = match char_type {
                    crate::ast::StringCharType::Char => 1,
                    crate::ast::StringCharType::WChar => 2,
                };
                Self {
                    alignment: 4, // Conformance data
                    size: 0, // Variable
                    is_variable: true,
                    has_conformant: true,
                }
            }

            ResolvedTypeKind::Named(_) => {
                // Need to look up from symbol table
                // Return conservative values
                Self {
                    alignment: ty.alignment,
                    size: ty.wire_size,
                    is_variable: ty.wire_size == 0,
                    has_conformant: false,
                }
            }
        }
    }

    /// Calculate padding needed before this type at a given position
    pub fn padding_at(&self, position: usize) -> usize {
        if self.alignment <= 1 {
            return 0;
        }
        let remainder = position % self.alignment;
        if remainder == 0 {
            0
        } else {
            self.alignment - remainder
        }
    }
}

/// Get alignment and size for a primitive type
fn primitive_layout(prim: PrimitiveType) -> (usize, usize) {
    match prim {
        PrimitiveType::Boolean => (1, 1),
        PrimitiveType::Byte => (1, 1),
        PrimitiveType::Char => (1, 1),
        PrimitiveType::Small => (1, 1),
        PrimitiveType::USmall => (1, 1),
        PrimitiveType::WChar => (2, 2),
        PrimitiveType::Short => (2, 2),
        PrimitiveType::UShort => (2, 2),
        PrimitiveType::Long => (4, 4),
        PrimitiveType::ULong => (4, 4),
        PrimitiveType::Float => (4, 4),
        PrimitiveType::ErrorStatusT => (4, 4),
        PrimitiveType::HandleT => (4, 4),
        PrimitiveType::Hyper => (8, 8),
        PrimitiveType::UHyper => (8, 8),
        PrimitiveType::Double => (8, 8),
    }
}

/// Calculate struct field offsets
pub fn calculate_struct_layout(fields: &[(String, ResolvedType)]) -> Vec<(String, usize, NdrLayout)> {
    let mut result = Vec::new();
    let mut offset = 0;

    for (name, ty) in fields {
        let layout = NdrLayout::for_type(ty);
        let padding = layout.padding_at(offset);
        offset += padding;

        result.push((name.clone(), offset, layout.clone()));

        if !layout.is_variable {
            offset += layout.size;
        }
    }

    result
}

/// Calculate union arm offsets (all start at same position after discriminant)
pub fn calculate_union_layout(
    switch_type: &ResolvedType,
    arms: &[(Option<ResolvedType>, Option<String>)],
) -> (NdrLayout, Vec<NdrLayout>) {
    let switch_layout = NdrLayout::for_type(switch_type);

    let arm_layouts: Vec<_> = arms.iter()
        .map(|(ty, _)| {
            ty.as_ref()
                .map(NdrLayout::for_type)
                .unwrap_or(NdrLayout {
                    alignment: 1,
                    size: 0,
                    is_variable: false,
                    has_conformant: false,
                })
        })
        .collect();

    (switch_layout, arm_layouts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::ast::PointerKind;

    #[test]
    fn test_primitive_layouts() {
        let bool_ty = ResolvedType {
            kind: ResolvedTypeKind::Primitive(PrimitiveType::Boolean),
            alignment: 1,
            wire_size: 1,
        };
        let layout = NdrLayout::for_type(&bool_ty);
        assert_eq!(layout.alignment, 1);
        assert_eq!(layout.size, 1);

        let long_ty = ResolvedType {
            kind: ResolvedTypeKind::Primitive(PrimitiveType::Long),
            alignment: 4,
            wire_size: 4,
        };
        let layout = NdrLayout::for_type(&long_ty);
        assert_eq!(layout.alignment, 4);
        assert_eq!(layout.size, 4);

        let hyper_ty = ResolvedType {
            kind: ResolvedTypeKind::Primitive(PrimitiveType::Hyper),
            alignment: 8,
            wire_size: 8,
        };
        let layout = NdrLayout::for_type(&hyper_ty);
        assert_eq!(layout.alignment, 8);
        assert_eq!(layout.size, 8);
    }

    #[test]
    fn test_padding_calculation() {
        let layout = NdrLayout {
            alignment: 4,
            size: 4,
            is_variable: false,
            has_conformant: false,
        };

        assert_eq!(layout.padding_at(0), 0);
        assert_eq!(layout.padding_at(1), 3);
        assert_eq!(layout.padding_at(2), 2);
        assert_eq!(layout.padding_at(3), 1);
        assert_eq!(layout.padding_at(4), 0);
    }

    #[test]
    fn test_fixed_array_layout() {
        let elem = ResolvedType {
            kind: ResolvedTypeKind::Primitive(PrimitiveType::Long),
            alignment: 4,
            wire_size: 4,
        };
        let array_ty = ResolvedType {
            kind: ResolvedTypeKind::FixedArray {
                element: Box::new(elem),
                size: 10,
            },
            alignment: 4,
            wire_size: 40,
        };

        let layout = NdrLayout::for_type(&array_ty);
        assert_eq!(layout.alignment, 4);
        assert_eq!(layout.size, 40);
        assert!(!layout.is_variable);
    }

    #[test]
    fn test_conformant_array_layout() {
        let elem = ResolvedType {
            kind: ResolvedTypeKind::Primitive(PrimitiveType::Byte),
            alignment: 1,
            wire_size: 1,
        };
        let array_ty = ResolvedType {
            kind: ResolvedTypeKind::ConformantArray {
                element: Box::new(elem),
                size_is: "n".to_string(),
            },
            alignment: 4,
            wire_size: 0,
        };

        let layout = NdrLayout::for_type(&array_ty);
        assert_eq!(layout.alignment, 4); // For max_count
        assert!(layout.is_variable);
        assert!(layout.has_conformant);
    }
}
