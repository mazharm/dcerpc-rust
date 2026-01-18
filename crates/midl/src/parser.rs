//! MIDL Parser
//!
//! Parses MIDL IDL source code into an AST using winnow parser combinators.

use crate::ast::*;
use crate::error::{MidlError, Result};
use crate::lexer::{Lexer, SpannedToken, Token};

/// Parse an IDL string into an AST
pub fn parse(input: &str) -> Result<File> {
    let mut lexer = Lexer::new(input);
    let tokens = lexer.tokenize()?;
    let mut parser = Parser::new(&tokens);
    parser.parse_file()
}

/// Parser state
struct Parser<'a> {
    tokens: &'a [SpannedToken],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [SpannedToken]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn current(&self) -> &Token {
        &self.tokens.get(self.pos).map(|t| &t.token).unwrap_or(&Token::Eof)
    }

    fn current_pos(&self) -> usize {
        self.tokens.get(self.pos).map(|t| t.span.start).unwrap_or(0)
    }

    fn advance(&mut self) {
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        if self.current() == expected {
            self.advance();
            Ok(())
        } else {
            Err(MidlError::parse(
                self.current_pos(),
                format!("expected {:?}, got {:?}", expected, self.current()),
            ))
        }
    }

    fn expect_ident(&mut self) -> Result<String> {
        match self.current() {
            Token::Ident(s) => {
                let s = s.clone();
                self.advance();
                Ok(s)
            }
            _ => Err(MidlError::parse(
                self.current_pos(),
                format!("expected identifier, got {:?}", self.current()),
            )),
        }
    }

    fn expect_integer(&mut self) -> Result<i64> {
        // Handle optional unary minus for negative numbers
        let negative = if *self.current() == Token::Minus {
            self.advance();
            true
        } else {
            false
        };

        match self.current() {
            Token::Integer(n) | Token::HexInteger(n) => {
                let n = *n;
                self.advance();
                Ok(if negative { -n } else { n })
            }
            _ => Err(MidlError::parse(
                self.current_pos(),
                format!("expected integer, got {:?}", self.current()),
            )),
        }
    }

    fn expect_string(&mut self) -> Result<String> {
        match self.current() {
            Token::StringLiteral(s) | Token::UuidLiteral(s) => {
                let s = s.clone();
                self.advance();
                Ok(s)
            }
            _ => Err(MidlError::parse(
                self.current_pos(),
                format!("expected string, got {:?}", self.current()),
            )),
        }
    }

    fn parse_file(&mut self) -> Result<File> {
        let mut items = Vec::new();

        while *self.current() != Token::Eof {
            items.push(self.parse_item()?);
        }

        Ok(File { items })
    }

    fn parse_item(&mut self) -> Result<Item> {
        // Check for cpp_quote first
        if *self.current() == Token::CppQuote {
            return self.parse_cpp_quote();
        }

        // Parse attributes if present
        let attrs = if *self.current() == Token::LBracket {
            self.parse_attributes()?
        } else {
            Vec::new()
        };

        match self.current() {
            Token::Import => self.parse_import(),
            Token::Typedef => self.parse_typedef(attrs),
            Token::Struct => self.parse_struct(attrs),
            Token::Enum => self.parse_enum(attrs),
            Token::Union => self.parse_union(attrs),
            Token::Interface => self.parse_interface(attrs),
            Token::Coclass => self.parse_coclass(attrs),
            Token::Library => self.parse_library(attrs),
            _ => Err(MidlError::parse(
                self.current_pos(),
                format!("unexpected token: {:?}", self.current()),
            )),
        }
    }

    fn parse_attributes(&mut self) -> Result<Vec<Attribute>> {
        self.expect(&Token::LBracket)?;
        let mut attrs = Vec::new();

        loop {
            attrs.push(self.parse_attribute()?);

            if *self.current() == Token::Comma {
                self.advance();
            } else {
                break;
            }
        }

        self.expect(&Token::RBracket)?;
        Ok(attrs)
    }

    fn parse_attribute(&mut self) -> Result<Attribute> {
        let attr = match self.current() {
            Token::Uuid => {
                self.advance();
                self.expect(&Token::LParen)?;
                let uuid = self.parse_uuid_value()?;
                self.expect(&Token::RParen)?;
                Attribute::Uuid(uuid)
            }
            Token::Version => {
                self.advance();
                self.expect(&Token::LParen)?;
                // Version can be written as "1.0" (parsed as float) or "1,0" (comma separated)
                let (major, minor) = match self.current() {
                    Token::Float_(f) => {
                        let f = *f;
                        self.advance();
                        let major = f.trunc() as u16;
                        let minor = ((f.fract() * 10.0).round()) as u16;
                        (major, minor)
                    }
                    _ => {
                        let major = self.expect_integer()? as u16;
                        // Accept either dot or comma as separator
                        if *self.current() == Token::Dot || *self.current() == Token::Comma {
                            self.advance();
                        }
                        let minor = self.expect_integer()? as u16;
                        (major, minor)
                    }
                };
                self.expect(&Token::RParen)?;
                Attribute::Version(major, minor)
            }
            Token::Object => {
                self.advance();
                Attribute::Object
            }
            Token::Local => {
                self.advance();
                Attribute::Local
            }
            Token::In => {
                self.advance();
                Attribute::In
            }
            Token::Out => {
                self.advance();
                Attribute::Out
            }
            Token::Retval => {
                self.advance();
                Attribute::Retval
            }
            Token::String => {
                self.advance();
                Attribute::String
            }
            Token::Ref => {
                self.advance();
                Attribute::Ref
            }
            Token::Unique => {
                self.advance();
                Attribute::Unique
            }
            Token::Ptr => {
                self.advance();
                Attribute::Ptr
            }
            Token::Default => {
                self.advance();
                Attribute::Default
            }
            Token::Ident(name) => {
                let name = name.clone();
                self.advance();

                // Check for known attributes with arguments
                match name.as_str() {
                    "size_is" => {
                        self.expect(&Token::LParen)?;
                        let expr = self.parse_attr_expr()?;
                        self.expect(&Token::RParen)?;
                        Attribute::SizeIs(expr)
                    }
                    "length_is" => {
                        self.expect(&Token::LParen)?;
                        let expr = self.parse_attr_expr()?;
                        self.expect(&Token::RParen)?;
                        Attribute::LengthIs(expr)
                    }
                    "max_is" => {
                        self.expect(&Token::LParen)?;
                        let expr = self.parse_attr_expr()?;
                        self.expect(&Token::RParen)?;
                        Attribute::MaxIs(expr)
                    }
                    "first_is" => {
                        self.expect(&Token::LParen)?;
                        let expr = self.parse_attr_expr()?;
                        self.expect(&Token::RParen)?;
                        Attribute::FirstIs(expr)
                    }
                    "last_is" => {
                        self.expect(&Token::LParen)?;
                        let expr = self.parse_attr_expr()?;
                        self.expect(&Token::RParen)?;
                        Attribute::LastIs(expr)
                    }
                    "switch_type" => {
                        self.expect(&Token::LParen)?;
                        let ty = self.expect_ident()?;
                        self.expect(&Token::RParen)?;
                        Attribute::SwitchType(ty)
                    }
                    "switch_is" => {
                        self.expect(&Token::LParen)?;
                        let expr = self.parse_attr_expr()?;
                        self.expect(&Token::RParen)?;
                        Attribute::SwitchIs(expr)
                    }
                    "case" => {
                        self.expect(&Token::LParen)?;
                        let value = self.expect_integer()?;
                        self.expect(&Token::RParen)?;
                        Attribute::Case(value)
                    }
                    "pointer_default" => {
                        self.expect(&Token::LParen)?;
                        let kind = match self.current() {
                            Token::Ref => { self.advance(); PointerKind::Ref }
                            Token::Unique => { self.advance(); PointerKind::Unique }
                            Token::Ptr => { self.advance(); PointerKind::Full }
                            _ => return Err(MidlError::parse(
                                self.current_pos(),
                                "expected pointer kind",
                            )),
                        };
                        self.expect(&Token::RParen)?;
                        Attribute::PointerDefault(kind)
                    }
                    "v1_enum" => Attribute::V1Enum,
                    "range" => {
                        self.expect(&Token::LParen)?;
                        let min = self.expect_integer()?;
                        self.expect(&Token::Comma)?;
                        let max = self.expect_integer()?;
                        self.expect(&Token::RParen)?;
                        Attribute::Range(min, max)
                    }
                    "endpoint" => {
                        self.expect(&Token::LParen)?;
                        let mut endpoints = Vec::new();
                        loop {
                            endpoints.push(self.expect_string()?);
                            if *self.current() == Token::Comma {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                        self.expect(&Token::RParen)?;
                        Attribute::Endpoint(endpoints)
                    }
                    "helpstring" => {
                        self.expect(&Token::LParen)?;
                        let s = self.expect_string()?;
                        self.expect(&Token::RParen)?;
                        Attribute::HelpString(s)
                    }
                    "id" => {
                        self.expect(&Token::LParen)?;
                        let id = self.expect_integer()? as i32;
                        self.expect(&Token::RParen)?;
                        Attribute::Id(id)
                    }
                    "propget" => Attribute::PropGet,
                    "propput" => Attribute::PropPut,
                    "propputref" => Attribute::PropPutRef,
                    "iid_is" => {
                        self.expect(&Token::LParen)?;
                        let param = self.expect_ident()?;
                        self.expect(&Token::RParen)?;
                        Attribute::IidIs(param)
                    }
                    "call_as" => {
                        self.expect(&Token::LParen)?;
                        let name = self.expect_ident()?;
                        self.expect(&Token::RParen)?;
                        Attribute::CallAs(name)
                    }
                    _ => {
                        // Unknown attribute - try to parse optional argument
                        let arg = if *self.current() == Token::LParen {
                            self.advance();
                            let arg = self.parse_attr_expr()?;
                            self.expect(&Token::RParen)?;
                            Some(arg)
                        } else {
                            None
                        };
                        Attribute::Unknown(name, arg)
                    }
                }
            }
            _ => {
                return Err(MidlError::parse(
                    self.current_pos(),
                    format!("unexpected attribute token: {:?}", self.current()),
                ))
            }
        };

        Ok(attr)
    }

    fn parse_attr_expr(&mut self) -> Result<String> {
        // Simple expression parsing - just collect tokens until ) or ,
        let mut expr = String::new();
        let mut depth = 0;

        loop {
            match self.current() {
                Token::LParen => {
                    depth += 1;
                    expr.push('(');
                    self.advance();
                }
                Token::RParen if depth == 0 => break,
                Token::RParen => {
                    depth -= 1;
                    expr.push(')');
                    self.advance();
                }
                Token::Comma if depth == 0 => break,
                Token::Ident(s) => {
                    expr.push_str(s);
                    self.advance();
                }
                Token::Integer(n) => {
                    expr.push_str(&n.to_string());
                    self.advance();
                }
                Token::Star => {
                    expr.push('*');
                    self.advance();
                }
                Token::Eof => break,
                _ => {
                    self.advance();
                }
            }
        }

        Ok(expr)
    }

    fn parse_uuid_value(&mut self) -> Result<String> {
        // UUID can be a string literal or a bare hex sequence
        match self.current() {
            Token::StringLiteral(s) | Token::UuidLiteral(s) => {
                let s = s.clone();
                self.advance();
                Ok(s)
            }
            Token::Ident(_) | Token::HexInteger(_) | Token::Integer(_) => {
                // Collect the UUID parts (e.g., 12345678-1234-1234-1234-123456789012)
                let mut parts = Vec::new();
                parts.push(self.parse_uuid_part()?);
                for _ in 0..4 {
                    if *self.current() == Token::Minus {
                        self.advance();
                    }
                    parts.push(self.parse_uuid_part()?);
                }
                Ok(parts.join("-"))
            }
            _ => Err(MidlError::parse(self.current_pos(), "expected UUID")),
        }
    }

    fn parse_uuid_part(&mut self) -> Result<String> {
        // UUID parts in MIDL are written as hex digits without 0x prefix
        // So we treat integers literally as their string representation
        match self.current() {
            Token::Ident(s) => {
                let s = s.clone();
                self.advance();
                Ok(s)
            }
            Token::HexInteger(n) => {
                // For explicit hex (0x...), convert back to hex string
                let s = format!("{:x}", n);
                self.advance();
                Ok(s)
            }
            Token::Integer(n) => {
                // For UUID parts, the decimal digits ARE the hex representation
                // e.g., 12345678 in uuid() means hex 12345678, not decimal->hex
                let s = format!("{}", n);
                self.advance();
                Ok(s)
            }
            _ => Err(MidlError::parse(self.current_pos(), "expected UUID part")),
        }
    }

    fn parse_import(&mut self) -> Result<Item> {
        self.expect(&Token::Import)?;
        let filename = self.expect_string()?;
        self.expect(&Token::Semicolon)?;
        Ok(Item::Import(Import { filename, span: None }))
    }

    fn parse_cpp_quote(&mut self) -> Result<Item> {
        self.expect(&Token::CppQuote)?;
        self.expect(&Token::LParen)?;
        let content = self.expect_string()?;
        self.expect(&Token::RParen)?;
        Ok(Item::CppQuote(content))
    }

    fn parse_typedef(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Typedef)?;

        // Check for inline struct/enum/union definition
        match self.current() {
            Token::Struct => {
                return self.parse_typedef_struct(attrs);
            }
            Token::Enum => {
                return self.parse_typedef_enum(attrs);
            }
            Token::Union => {
                return self.parse_typedef_union(attrs);
            }
            _ => {}
        }

        let base_type = self.parse_type()?;
        let name = self.expect_ident()?;

        // Check for array suffix
        let final_type = if *self.current() == Token::LBracket {
            self.parse_array_suffix(base_type)?
        } else {
            base_type
        };

        self.expect(&Token::Semicolon)?;

        Ok(Item::Typedef(Typedef {
            attrs,
            base_type: final_type,
            name,
            span: None,
        }))
    }

    fn parse_typedef_struct(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Struct)?;

        // Optional tag name (e.g., _Point in "struct _Point")
        let _tag_name = if let Token::Ident(_) = self.current() {
            Some(self.expect_ident()?)
        } else {
            None
        };

        // Inline definition
        self.expect(&Token::LBrace)?;

        let mut fields = Vec::new();
        while *self.current() != Token::RBrace {
            fields.push(self.parse_field()?);
        }

        self.expect(&Token::RBrace)?;

        // The alias name after the closing brace
        let name = self.expect_ident()?;

        self.expect(&Token::Semicolon)?;

        // Create a struct with the alias name (or tag name if no alias)
        Ok(Item::Struct(Struct {
            attrs,
            name,
            fields,
            span: None,
        }))
    }

    fn parse_typedef_enum(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Enum)?;

        // Optional tag name
        let _tag_name = if let Token::Ident(_) = self.current() {
            Some(self.expect_ident()?)
        } else {
            None
        };

        // Inline definition
        self.expect(&Token::LBrace)?;

        let mut variants = Vec::new();
        let mut next_value: i64 = 0;

        while *self.current() != Token::RBrace {
            let var_name = self.expect_ident()?;
            let value = if *self.current() == Token::Equals {
                self.advance();
                let v = self.expect_integer()?;
                next_value = v + 1;
                Some(v)
            } else {
                let v = next_value;
                next_value += 1;
                Some(v)
            };

            variants.push(EnumVariant {
                name: var_name,
                value,
                span: None,
            });

            // Optional comma
            if *self.current() == Token::Comma {
                self.advance();
            }
        }

        self.expect(&Token::RBrace)?;

        // The alias name
        let name = self.expect_ident()?;

        self.expect(&Token::Semicolon)?;

        Ok(Item::Enum(Enum {
            attrs,
            name,
            variants,
            span: None,
        }))
    }

    fn parse_typedef_union(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Union)?;

        // Optional tag name
        let _tag_name = if let Token::Ident(_) = self.current() {
            Some(self.expect_ident()?)
        } else {
            None
        };

        // Inline definition
        self.expect(&Token::LBrace)?;

        let mut arms = Vec::new();

        while *self.current() != Token::RBrace {
            let arm = self.parse_union_arm()?;
            arms.push(arm);
        }

        self.expect(&Token::RBrace)?;

        // The alias name
        let name = self.expect_ident()?;

        self.expect(&Token::Semicolon)?;

        Ok(Item::Union(Union {
            attrs,
            name,
            switch_type: Type::Base(BaseType::Long), // Default switch type
            switch_is: None,
            arms,
            span: None,
        }))
    }

    fn parse_struct(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Struct)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut fields = Vec::new();
        while *self.current() != Token::RBrace {
            fields.push(self.parse_field()?);
        }

        self.expect(&Token::RBrace)?;
        // Optional semicolon
        if *self.current() == Token::Semicolon {
            self.advance();
        }

        Ok(Item::Struct(Struct {
            attrs,
            name,
            fields,
            span: None,
        }))
    }

    fn parse_field(&mut self) -> Result<Field> {
        // Optional attributes
        let attrs = if *self.current() == Token::LBracket {
            self.parse_attributes()?
        } else {
            Vec::new()
        };

        let ty = self.parse_type()?;
        let name = self.expect_ident()?;

        // Check for array suffix
        let final_type = if *self.current() == Token::LBracket {
            self.parse_array_suffix(ty)?
        } else {
            ty
        };

        self.expect(&Token::Semicolon)?;

        Ok(Field {
            attrs,
            ty: final_type,
            name,
            span: None,
        })
    }

    fn parse_enum(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Enum)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut variants = Vec::new();
        let mut next_value: i64 = 0;

        while *self.current() != Token::RBrace {
            let var_name = self.expect_ident()?;
            let value = if *self.current() == Token::Equals {
                self.advance();
                let v = self.expect_integer()?;
                next_value = v + 1;
                Some(v)
            } else {
                let v = next_value;
                next_value += 1;
                Some(v)
            };

            variants.push(EnumVariant {
                name: var_name,
                value,
                span: None,
            });

            if *self.current() == Token::Comma {
                self.advance();
            }
        }

        self.expect(&Token::RBrace)?;
        // Optional semicolon
        if *self.current() == Token::Semicolon {
            self.advance();
        }

        Ok(Item::Enum(Enum {
            attrs,
            name,
            variants,
            span: None,
        }))
    }

    fn parse_union(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Union)?;

        // Check for switch clause
        let (switch_type, switch_is) = if *self.current() == Token::Switch {
            self.advance();
            self.expect(&Token::LParen)?;
            let st = self.parse_type()?;
            let si = if *self.current() != Token::RParen {
                Some(self.expect_ident()?)
            } else {
                None
            };
            self.expect(&Token::RParen)?;
            (st, si)
        } else {
            (Type::Base(BaseType::Long), None)
        };

        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut arms = Vec::new();
        while *self.current() != Token::RBrace {
            arms.push(self.parse_union_arm()?);
        }

        self.expect(&Token::RBrace)?;
        if *self.current() == Token::Semicolon {
            self.advance();
        }

        Ok(Item::Union(Union {
            attrs,
            name,
            switch_type,
            switch_is,
            arms,
            span: None,
        }))
    }

    fn parse_union_arm(&mut self) -> Result<UnionArm> {
        let mut cases = Vec::new();

        // Parse case labels
        loop {
            match self.current() {
                Token::Case => {
                    self.advance();
                    let value = self.expect_integer()?;
                    self.expect(&Token::Colon)?;
                    cases.push(UnionCase::Value(value));
                }
                Token::Default => {
                    self.advance();
                    self.expect(&Token::Colon)?;
                    cases.push(UnionCase::Default);
                }
                Token::LBracket => {
                    // Attribute with case
                    let attrs = self.parse_attributes()?;
                    for attr in attrs {
                        if let Attribute::Case(v) = attr {
                            cases.push(UnionCase::Value(v));
                        }
                    }
                }
                _ => break,
            }
        }

        // Parse the arm content (type and name, or empty)
        let (ty, name) = if *self.current() == Token::Semicolon {
            self.advance();
            (None, None)
        } else {
            let t = self.parse_type()?;
            let n = self.expect_ident()?;
            self.expect(&Token::Semicolon)?;
            (Some(t), Some(n))
        };

        Ok(UnionArm {
            cases,
            ty,
            name,
            span: None,
        })
    }

    fn parse_interface(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Interface)?;
        let name = self.expect_ident()?;

        // Check for base interface
        let base = if *self.current() == Token::Colon {
            self.advance();
            Some(self.expect_ident()?)
        } else {
            None
        };

        self.expect(&Token::LBrace)?;

        let mut methods = Vec::new();
        while *self.current() != Token::RBrace {
            methods.push(self.parse_method()?);
        }

        self.expect(&Token::RBrace)?;
        if *self.current() == Token::Semicolon {
            self.advance();
        }

        Ok(Item::Interface(Interface {
            attrs,
            name,
            base,
            methods,
            span: None,
        }))
    }

    fn parse_method(&mut self) -> Result<Method> {
        // Optional attributes
        let attrs = if *self.current() == Token::LBracket {
            self.parse_attributes()?
        } else {
            Vec::new()
        };

        let return_type = self.parse_type()?;
        let name = self.expect_ident()?;

        self.expect(&Token::LParen)?;

        let mut params = Vec::new();
        if *self.current() != Token::RParen {
            loop {
                params.push(self.parse_param()?);
                if *self.current() == Token::Comma {
                    self.advance();
                } else {
                    break;
                }
            }
        }

        self.expect(&Token::RParen)?;
        self.expect(&Token::Semicolon)?;

        Ok(Method {
            attrs,
            return_type,
            name,
            params,
            span: None,
        })
    }

    fn parse_param(&mut self) -> Result<Param> {
        // Optional attributes
        let attrs = if *self.current() == Token::LBracket {
            self.parse_attributes()?
        } else {
            Vec::new()
        };

        let ty = self.parse_type()?;
        let name = self.expect_ident()?;

        // Check for array suffix
        let final_type = if *self.current() == Token::LBracket {
            self.parse_array_suffix(ty)?
        } else {
            ty
        };

        Ok(Param {
            attrs,
            ty: final_type,
            name,
            span: None,
        })
    }

    fn parse_coclass(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Coclass)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut interfaces = Vec::new();
        while *self.current() != Token::RBrace {
            // Optional attributes
            let iface_attrs = if *self.current() == Token::LBracket {
                self.parse_attributes()?
            } else {
                Vec::new()
            };

            self.expect(&Token::Interface)?;
            let iface_name = self.expect_ident()?;
            self.expect(&Token::Semicolon)?;

            let is_default = iface_attrs.iter().any(|a| matches!(a, Attribute::Default));
            let is_source = iface_attrs.iter().any(|a| {
                matches!(a, Attribute::Unknown(n, _) if n == "source")
            });

            interfaces.push(CoclassInterface {
                attrs: iface_attrs,
                name: iface_name,
                is_default,
                is_source,
            });
        }

        self.expect(&Token::RBrace)?;
        if *self.current() == Token::Semicolon {
            self.advance();
        }

        Ok(Item::Coclass(Coclass {
            attrs,
            name,
            interfaces,
            span: None,
        }))
    }

    fn parse_library(&mut self, attrs: Vec<Attribute>) -> Result<Item> {
        self.expect(&Token::Library)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut items = Vec::new();
        while *self.current() != Token::RBrace {
            items.push(self.parse_item()?);
        }

        self.expect(&Token::RBrace)?;
        if *self.current() == Token::Semicolon {
            self.advance();
        }

        Ok(Item::Library(Library {
            attrs,
            name,
            items,
            span: None,
        }))
    }

    fn parse_type(&mut self) -> Result<Type> {
        // Check for unsigned prefix
        let unsigned = if *self.current() == Token::Unsigned {
            self.advance();
            true
        } else {
            false
        };

        let base = match self.current() {
            Token::Void => { self.advance(); Type::Base(BaseType::Void) }
            Token::Boolean => { self.advance(); Type::Base(BaseType::Boolean) }
            Token::Byte => { self.advance(); Type::Base(BaseType::Byte) }
            Token::Char => { self.advance(); Type::Base(BaseType::Char) }
            Token::Wchar_t => { self.advance(); Type::Base(BaseType::WChar) }
            Token::Small => {
                self.advance();
                Type::Base(if unsigned { BaseType::USmall } else { BaseType::Small })
            }
            Token::Short => {
                self.advance();
                Type::Base(if unsigned { BaseType::UShort } else { BaseType::Short })
            }
            Token::Long => {
                self.advance();
                Type::Base(if unsigned { BaseType::ULong } else { BaseType::Long })
            }
            Token::Hyper => {
                self.advance();
                Type::Base(if unsigned { BaseType::UHyper } else { BaseType::Hyper })
            }
            Token::Int => {
                self.advance();
                Type::Base(if unsigned { BaseType::ULong } else { BaseType::Int })
            }
            Token::Int32 => { self.advance(); Type::Base(BaseType::Int32) }
            Token::Int64 => { self.advance(); Type::Base(BaseType::Int64) }
            Token::Float => { self.advance(); Type::Base(BaseType::Float) }
            Token::Double => { self.advance(); Type::Base(BaseType::Double) }
            Token::Error_status_t => { self.advance(); Type::Base(BaseType::ErrorStatusT) }
            Token::Handle_t => { self.advance(); Type::Base(BaseType::HandleT) }
            Token::Struct => {
                self.advance();
                let name = self.expect_ident()?;
                Type::Named(name)
            }
            Token::Enum => {
                self.advance();
                let name = self.expect_ident()?;
                Type::Named(name)
            }
            Token::Union => {
                self.advance();
                let name = self.expect_ident()?;
                Type::Named(name)
            }
            Token::Ident(name) => {
                let name = name.clone();
                self.advance();
                Type::Named(name)
            }
            _ => {
                return Err(MidlError::parse(
                    self.current_pos(),
                    format!("expected type, got {:?}", self.current()),
                ))
            }
        };

        // Check for pointer
        let mut ty = base;
        while *self.current() == Token::Star {
            self.advance();
            ty = Type::Pointer(PointerType {
                pointee: Box::new(ty),
                kind: PointerKind::default(),
            });
        }

        Ok(ty)
    }

    fn parse_array_suffix(&mut self, element: Type) -> Result<Type> {
        self.expect(&Token::LBracket)?;

        let size = if *self.current() == Token::RBracket {
            // Empty brackets - conformant (size determined by attribute)
            ArraySize::Conformant { size_is: String::new() }
        } else {
            let n = self.expect_integer()? as usize;
            ArraySize::Fixed(n)
        };

        self.expect(&Token::RBracket)?;

        Ok(Type::Array(ArrayType {
            element: Box::new(element),
            size,
        }))
    }
}

// Add Token::Minus for UUID parsing
#[allow(dead_code)]
impl Token {
    const fn is_minus(&self) -> bool {
        matches!(self, Token::Integer(n) if *n < 0)
    }
}

// Placeholder for minus token matching in UUID
#[allow(dead_code)]
#[allow(non_upper_case_globals)]
const Token_Minus: Token = Token::Integer(0); // Hack: we don't actually have a minus token

impl PartialEq<Token> for Token {
    fn eq(&self, other: &Token) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
            && match (self, other) {
                (Token::Ident(a), Token::Ident(b)) => a == b,
                (Token::Integer(a), Token::Integer(b)) => a == b,
                (Token::HexInteger(a), Token::HexInteger(b)) => a == b,
                (Token::Float_(a), Token::Float_(b)) => (a - b).abs() < f64::EPSILON,
                (Token::StringLiteral(a), Token::StringLiteral(b)) => a == b,
                (Token::UuidLiteral(a), Token::UuidLiteral(b)) => a == b,
                _ => true, // For unit variants
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_interface() {
        let input = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface ICalculator {
                long Add([in] long a, [in] long b);
            }
        "#;

        let file = parse(input).unwrap();
        assert_eq!(file.items.len(), 1);

        if let Item::Interface(iface) = &file.items[0] {
            assert_eq!(iface.name, "ICalculator");
            assert_eq!(iface.methods.len(), 1);
            assert_eq!(iface.methods[0].name, "Add");
            assert_eq!(iface.methods[0].params.len(), 2);
        } else {
            panic!("expected interface");
        }
    }

    #[test]
    fn test_struct() {
        let input = r#"
            typedef struct _Point {
                long x;
                long y;
            } Point;
        "#;

        let file = parse(input).unwrap();
        // This will be parsed as typedef
        assert_eq!(file.items.len(), 1);
    }

    #[test]
    fn test_enum() {
        let input = r#"
            typedef enum _Color {
                Red = 0,
                Green = 1,
                Blue = 2
            } Color;
        "#;

        let file = parse(input).unwrap();
        assert_eq!(file.items.len(), 1);
    }

    #[test]
    fn test_pointer_params() {
        let input = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface ITest {
                long GetValue([out] long* value);
                void SetData([in, size_is(len)] byte* data, [in] long len);
            }
        "#;

        let file = parse(input).unwrap();
        if let Item::Interface(iface) = &file.items[0] {
            assert_eq!(iface.methods.len(), 2);
        } else {
            panic!("expected interface");
        }
    }
}
