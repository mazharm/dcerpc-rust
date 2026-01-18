//! MIDL Lexer
//!
//! Tokenizes MIDL IDL source code.

use crate::error::{MidlError, Result, Span};

/// Token types
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum Token {
    // Keywords
    Boolean,
    Byte,
    Case,
    Char,
    Coclass,
    Const,
    Default,
    Double,
    Enum,
    Error_status_t,
    Float,
    Handle_t,
    Hyper,
    Import,
    In,
    Int,
    Int32,
    Int64,
    Interface,
    Library,
    Local,
    Long,
    Object,
    Out,
    Pipe,
    Ptr,
    Ref,
    Retval,
    Short,
    Small,
    String,
    Struct,
    Switch,
    Typedef,
    Union,
    Unique,
    Unsigned,
    Uuid,
    Version,
    Void,
    Wchar_t,
    CppQuote,

    // Identifiers and literals
    Ident(String),
    Integer(i64),
    HexInteger(i64),
    Float_(f64),
    StringLiteral(String),
    UuidLiteral(String),

    // Punctuation
    LBrace,      // {
    RBrace,      // }
    LBracket,    // [
    RBracket,    // ]
    LParen,      // (
    RParen,      // )
    Comma,       // ,
    Semicolon,   // ;
    Colon,       // :
    Star,        // *
    Equals,      // =
    Dot,         // .
    Minus,       // -
    Arrow,       // ->
    DoubleColon, // ::

    // End of file
    Eof,
}

impl Token {
    pub fn is_keyword(s: &str) -> Option<Token> {
        match s {
            "boolean" => Some(Token::Boolean),
            "byte" => Some(Token::Byte),
            "case" => Some(Token::Case),
            "char" => Some(Token::Char),
            "coclass" => Some(Token::Coclass),
            "const" => Some(Token::Const),
            "default" => Some(Token::Default),
            "double" => Some(Token::Double),
            "enum" => Some(Token::Enum),
            "error_status_t" => Some(Token::Error_status_t),
            "float" => Some(Token::Float),
            "handle_t" => Some(Token::Handle_t),
            "hyper" => Some(Token::Hyper),
            "import" => Some(Token::Import),
            "in" => Some(Token::In),
            "int" => Some(Token::Int),
            "__int32" => Some(Token::Int32),
            "__int64" => Some(Token::Int64),
            "interface" => Some(Token::Interface),
            "library" => Some(Token::Library),
            "local" => Some(Token::Local),
            "long" => Some(Token::Long),
            "object" => Some(Token::Object),
            "out" => Some(Token::Out),
            "pipe" => Some(Token::Pipe),
            "ptr" => Some(Token::Ptr),
            "ref" => Some(Token::Ref),
            "retval" => Some(Token::Retval),
            "short" => Some(Token::Short),
            "small" => Some(Token::Small),
            "string" => Some(Token::String),
            "struct" => Some(Token::Struct),
            "switch" => Some(Token::Switch),
            "typedef" => Some(Token::Typedef),
            "union" => Some(Token::Union),
            "unique" => Some(Token::Unique),
            "unsigned" => Some(Token::Unsigned),
            "uuid" => Some(Token::Uuid),
            "version" => Some(Token::Version),
            "void" => Some(Token::Void),
            "wchar_t" => Some(Token::Wchar_t),
            "cpp_quote" => Some(Token::CppQuote),
            _ => None,
        }
    }
}

/// A token with its source location
#[derive(Debug, Clone)]
pub struct SpannedToken {
    pub token: Token,
    pub span: Span,
}

/// Lexer state
pub struct Lexer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    /// Tokenize the entire input
    pub fn tokenize(&mut self) -> Result<Vec<SpannedToken>> {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token()?;
            let is_eof = tok.token == Token::Eof;
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        Ok(tokens)
    }

    /// Get the next token
    pub fn next_token(&mut self) -> Result<SpannedToken> {
        self.skip_whitespace_and_comments();

        let start = self.pos;

        if self.pos >= self.bytes.len() {
            return Ok(SpannedToken {
                token: Token::Eof,
                span: Span::at(self.pos),
            });
        }

        let ch = self.bytes[self.pos];

        // Single-character tokens
        let token = match ch {
            b'{' => { self.pos += 1; Token::LBrace }
            b'}' => { self.pos += 1; Token::RBrace }
            b'[' => { self.pos += 1; Token::LBracket }
            b']' => { self.pos += 1; Token::RBracket }
            b'(' => { self.pos += 1; Token::LParen }
            b')' => { self.pos += 1; Token::RParen }
            b',' => { self.pos += 1; Token::Comma }
            b';' => { self.pos += 1; Token::Semicolon }
            b'=' => { self.pos += 1; Token::Equals }
            b'*' => { self.pos += 1; Token::Star }
            b'.' => { self.pos += 1; Token::Dot }
            b':' => {
                self.pos += 1;
                if self.peek() == Some(b':') {
                    self.pos += 1;
                    Token::DoubleColon
                } else {
                    Token::Colon
                }
            }
            b'-' => {
                self.pos += 1;
                if self.peek() == Some(b'>') {
                    self.pos += 1;
                    Token::Arrow
                } else {
                    // Always emit minus; negative numbers handled by parser
                    Token::Minus
                }
            }
            b'"' => return self.lex_string(),
            b'0'..=b'9' => return self.lex_number(start, false),
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => return self.lex_ident(),
            _ => return Err(MidlError::lexer(self.pos, format!("unexpected character: {}", ch as char))),
        };

        Ok(SpannedToken {
            token,
            span: Span::new(start, self.pos),
        })
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }

            // Check for comments
            if self.pos + 1 < self.bytes.len() {
                if self.bytes[self.pos] == b'/' && self.bytes[self.pos + 1] == b'/' {
                    // Line comment
                    self.pos += 2;
                    while self.pos < self.bytes.len() && self.bytes[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                    continue;
                } else if self.bytes[self.pos] == b'/' && self.bytes[self.pos + 1] == b'*' {
                    // Block comment
                    self.pos += 2;
                    while self.pos + 1 < self.bytes.len() {
                        if self.bytes[self.pos] == b'*' && self.bytes[self.pos + 1] == b'/' {
                            self.pos += 2;
                            break;
                        }
                        self.pos += 1;
                    }
                    continue;
                }
            }

            break;
        }
    }

    fn lex_ident(&mut self) -> Result<SpannedToken> {
        let start = self.pos;

        while self.pos < self.bytes.len() {
            let ch = self.bytes[self.pos];
            if ch.is_ascii_alphanumeric() || ch == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }

        let s = &self.input[start..self.pos];

        let token = if let Some(kw) = Token::is_keyword(s) {
            kw
        } else {
            Token::Ident(s.to_string())
        };

        Ok(SpannedToken {
            token,
            span: Span::new(start, self.pos),
        })
    }

    fn lex_number(&mut self, start: usize, negative: bool) -> Result<SpannedToken> {
        // Check for hex
        if self.pos + 1 < self.bytes.len()
            && self.bytes[self.pos] == b'0'
            && (self.bytes[self.pos + 1] == b'x' || self.bytes[self.pos + 1] == b'X')
        {
            self.pos += 2;
            let hex_start = self.pos;
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_hexdigit() {
                self.pos += 1;
            }
            let hex_str = &self.input[hex_start..self.pos];
            let value = i64::from_str_radix(hex_str, 16)
                .map_err(|_| MidlError::lexer(start, "invalid hex number"))?;
            let value = if negative { -value } else { value };
            return Ok(SpannedToken {
                token: Token::HexInteger(value),
                span: Span::new(start, self.pos),
            });
        }

        // Decimal number
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
            self.pos += 1;
        }

        // Check for float
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'.' {
            self.pos += 1;
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            let num_str = &self.input[start..self.pos];
            let value: f64 = num_str.parse()
                .map_err(|_| MidlError::lexer(start, "invalid float"))?;
            return Ok(SpannedToken {
                token: Token::Float_(value),
                span: Span::new(start, self.pos),
            });
        }

        let num_start = if negative { start + 1 } else { start };
        let num_str = &self.input[num_start..self.pos];
        let value: i64 = num_str.parse()
            .map_err(|_| MidlError::lexer(start, "invalid integer"))?;
        let value = if negative { -value } else { value };

        Ok(SpannedToken {
            token: Token::Integer(value),
            span: Span::new(start, self.pos),
        })
    }

    fn lex_string(&mut self) -> Result<SpannedToken> {
        let start = self.pos;
        self.pos += 1; // Skip opening quote

        let mut s = String::new();
        while self.pos < self.bytes.len() && self.bytes[self.pos] != b'"' {
            if self.bytes[self.pos] == b'\\' && self.pos + 1 < self.bytes.len() {
                self.pos += 1;
                match self.bytes[self.pos] {
                    b'n' => s.push('\n'),
                    b'r' => s.push('\r'),
                    b't' => s.push('\t'),
                    b'\\' => s.push('\\'),
                    b'"' => s.push('"'),
                    ch => {
                        s.push('\\');
                        s.push(ch as char);
                    }
                }
            } else {
                s.push(self.bytes[self.pos] as char);
            }
            self.pos += 1;
        }

        if self.pos >= self.bytes.len() {
            return Err(MidlError::lexer(start, "unterminated string"));
        }

        self.pos += 1; // Skip closing quote

        // Check if it looks like a UUID
        let token = if is_uuid_format(&s) {
            Token::UuidLiteral(s)
        } else {
            Token::StringLiteral(s)
        };

        Ok(SpannedToken {
            token,
            span: Span::new(start, self.pos),
        })
    }
}

/// Check if a string looks like a UUID
fn is_uuid_format(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keywords() {
        let mut lexer = Lexer::new("interface struct enum union typedef");
        let tokens = lexer.tokenize().unwrap();
        assert!(matches!(tokens[0].token, Token::Interface));
        assert!(matches!(tokens[1].token, Token::Struct));
        assert!(matches!(tokens[2].token, Token::Enum));
        assert!(matches!(tokens[3].token, Token::Union));
        assert!(matches!(tokens[4].token, Token::Typedef));
    }

    #[test]
    fn test_identifiers() {
        let mut lexer = Lexer::new("IFoo myMethod _private");
        let tokens = lexer.tokenize().unwrap();
        assert!(matches!(&tokens[0].token, Token::Ident(s) if s == "IFoo"));
        assert!(matches!(&tokens[1].token, Token::Ident(s) if s == "myMethod"));
        assert!(matches!(&tokens[2].token, Token::Ident(s) if s == "_private"));
    }

    #[test]
    fn test_numbers() {
        let mut lexer = Lexer::new("42 0x1234 -10 3.14");
        let tokens = lexer.tokenize().unwrap();
        assert!(matches!(tokens[0].token, Token::Integer(42)));
        assert!(matches!(tokens[1].token, Token::HexInteger(0x1234)));
        // Negative numbers are now Minus followed by Integer (parser handles negation)
        assert!(matches!(tokens[2].token, Token::Minus));
        assert!(matches!(tokens[3].token, Token::Integer(10)));
        assert!(matches!(tokens[4].token, Token::Float_(f) if (f - 3.14).abs() < 0.001));
    }

    #[test]
    fn test_strings() {
        let mut lexer = Lexer::new(r#""hello" "12345678-1234-1234-1234-123456789012""#);
        let tokens = lexer.tokenize().unwrap();
        assert!(matches!(&tokens[0].token, Token::StringLiteral(s) if s == "hello"));
        assert!(matches!(&tokens[1].token, Token::UuidLiteral(_)));
    }

    #[test]
    fn test_punctuation() {
        let mut lexer = Lexer::new("{}[](),;:*=.");
        let tokens = lexer.tokenize().unwrap();
        assert!(matches!(tokens[0].token, Token::LBrace));
        assert!(matches!(tokens[1].token, Token::RBrace));
        assert!(matches!(tokens[2].token, Token::LBracket));
        assert!(matches!(tokens[3].token, Token::RBracket));
        assert!(matches!(tokens[4].token, Token::LParen));
        assert!(matches!(tokens[5].token, Token::RParen));
        assert!(matches!(tokens[6].token, Token::Comma));
        assert!(matches!(tokens[7].token, Token::Semicolon));
        assert!(matches!(tokens[8].token, Token::Colon));
        assert!(matches!(tokens[9].token, Token::Star));
        assert!(matches!(tokens[10].token, Token::Equals));
        assert!(matches!(tokens[11].token, Token::Dot));
    }

    #[test]
    fn test_comments() {
        let mut lexer = Lexer::new("a // line comment\nb /* block */ c");
        let tokens = lexer.tokenize().unwrap();
        assert!(matches!(&tokens[0].token, Token::Ident(s) if s == "a"));
        assert!(matches!(&tokens[1].token, Token::Ident(s) if s == "b"));
        assert!(matches!(&tokens[2].token, Token::Ident(s) if s == "c"));
    }

    #[test]
    fn test_interface_snippet() {
        let input = r#"
            [uuid(12345678-1234-1234-1234-123456789012), version(1.0)]
            interface IFoo {
                long Add([in] long a, [in] long b);
            }
        "#;
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize().unwrap();
        // Should have many tokens, check a few key ones
        assert!(tokens.iter().any(|t| matches!(t.token, Token::Interface)));
        assert!(tokens.iter().any(|t| matches!(&t.token, Token::Ident(s) if s == "IFoo")));
        assert!(tokens.iter().any(|t| matches!(t.token, Token::Long)));
    }
}
