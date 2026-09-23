//! JavaScript-like expression evaluator for filter_script and sort_script
//!
//! This module provides a lightweight expression evaluator that supports
//! common JS-like expressions used in subconverter for filtering and sorting nodes.
//! No JS engine dependency - pure Rust implementation.

use crate::subconverter::{ProxyNode, ProxyProtocol};
use std::collections::HashMap;

/// Represents a value in our expression evaluator
#[derive(Debug, Clone, PartialEq)]
pub enum JsValue {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
    Array(Vec<JsValue>),
    /// Placeholder for method references (e.g., "includes" method on string)
    Method(String),
}

impl From<String> for JsValue {
    fn from(s: String) -> Self {
        JsValue::Str(s)
    }
}

impl From<&str> for JsValue {
    fn from(s: &str) -> Self {
        JsValue::Str(s.to_string())
    }
}

impl From<usize> for JsValue {
    fn from(n: usize) -> Self {
        JsValue::Num(n as f64)
    }
}

impl From<i32> for JsValue {
    fn from(n: i32) -> Self {
        JsValue::Num(n as f64)
    }
}

impl From<u16> for JsValue {
    fn from(n: u16) -> Self {
        JsValue::Num(n as f64)
    }
}

impl From<bool> for JsValue {
    fn from(b: bool) -> Self {
        JsValue::Bool(b)
    }
}

impl std::fmt::Display for JsValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsValue::Str(s) => write!(f, "\"{}\"", s),
            JsValue::Num(n) => write!(f, "{}", n),
            JsValue::Bool(b) => write!(f, "{}", b),
            JsValue::Null => write!(f, "null"),
            JsValue::Method(name) => write!(f, "[method {}]", name),
            JsValue::Array(arr) => {
                write!(f, "[")?;
                for (i, v) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Context for node property access
pub struct NodeContext<'a> {
    pub node: &'a ProxyNode,
    pub other: Option<&'a ProxyNode>,
}

impl<'a> NodeContext<'a> {
    /// Get a property value from the node
    pub fn get_property(&self, prop: &str) -> JsValue {
        match prop {
            "name" => JsValue::Str(self.node.name.clone()),
            "server" => JsValue::Str(self.node.server.clone()),
            "port" => JsValue::Num(self.node.port as f64),
            "protocol" => JsValue::Str(protocol_to_string(&self.node.protocol)),
            "type" | "protocol_type" => JsValue::Str(protocol_to_string(&self.node.protocol)),
            // Extra fields
            "uuid" => self
                .node
                .extra
                .uuid
                .clone()
                .map(JsValue::Str)
                .unwrap_or(JsValue::Null),
            "password" => self
                .node
                .extra
                .password
                .clone()
                .map(JsValue::Str)
                .unwrap_or(JsValue::Null),
            "cipher" => self
                .node
                .extra
                .cipher
                .clone()
                .map(JsValue::Str)
                .unwrap_or(JsValue::Null),
            "sni" => self
                .node
                .extra
                .sni
                .clone()
                .map(JsValue::Str)
                .unwrap_or(JsValue::Null),
            "tls" => JsValue::Bool(self.node.extra.tls),
            // Other node properties
            "ip" | "address" => JsValue::Str(self.node.server.clone()),
            "country" | "region" | "city" => {
                // Try to extract from name if it looks like "🇺🇸 美国节点"
                extract_country_from_name(&self.node.name)
            }
            _ => JsValue::Null,
        }
    }

    /// Get 'other' node property (for sort comparisons)
    pub fn get_other_property(&self, prop: &str) -> JsValue {
        if let Some(other) = self.other {
            match prop {
                "name" => JsValue::Str(other.name.clone()),
                "server" => JsValue::Str(other.server.clone()),
                "port" => JsValue::Num(other.port as f64),
                "protocol" => JsValue::Str(protocol_to_string(&other.protocol)),
                _ => JsValue::Null,
            }
        } else {
            JsValue::Null
        }
    }
}

/// Convert protocol to string representation
fn protocol_to_string(protocol: &ProxyProtocol) -> String {
    match protocol {
        ProxyProtocol::Shadowsocks => "shadowsocks".to_string(),
        ProxyProtocol::ShadowSocksR => "shadowsocksr".to_string(),
        ProxyProtocol::VMess => "vmess".to_string(),
        ProxyProtocol::VLESS => "vless".to_string(),
        ProxyProtocol::Trojan => "trojan".to_string(),
        ProxyProtocol::Hysteria2 => "hysteria2".to_string(),
        ProxyProtocol::Tuic => "tuic".to_string(),
        ProxyProtocol::WireGuard => "wireguard".to_string(),
        ProxyProtocol::Unknown => "unknown".to_string(),
    }
}

/// JS-flavoured substring: indices are char positions (never bytes),
/// both clamped to the char count, and swapped when start > end —
/// mirrors String.prototype.substring instead of panicking.
fn js_substring(s: &str, start: usize, end: usize) -> String {
    let len = s.chars().count();
    let (mut a, mut b) = (start.min(len), end.min(len));
    if a > b {
        std::mem::swap(&mut a, &mut b);
    }
    s.chars().skip(a).take(b - a).collect()
}

/// Try to extract country/region from node name (shared marker table).
fn extract_country_from_name(name: &str) -> JsValue {
    match crate::subconverter::filters::detect_country(name) {
        Some(code) => JsValue::Str(code.to_string()),
        None => JsValue::Null,
    }
}

/// Token types for our expression parser
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Literals
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
    Identifier(String),

    // Operators
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulo,
    Equals,
    NotEquals,
    LessThan,
    GreaterThan,
    LessEquals,
    GreaterEquals,
    And,
    Or,
    Not,
    BitwiseNot,

    // Punctuation
    LParen,
    RParen,
    LBracket,
    RBracket,
    Dot,
    Comma,
    Semicolon,
    Colon,

    // Special
    Eof,
}

/// Expression node types
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    // Literals
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
    Identifier(String),

    // Unary operations
    Not(Box<Expr>),
    Negate(Box<Expr>),

    // Binary operations
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Equals(Box<Expr>, Box<Expr>),
    NotEquals(Box<Expr>, Box<Expr>),
    LessThan(Box<Expr>, Box<Expr>),
    GreaterThan(Box<Expr>, Box<Expr>),
    LessEquals(Box<Expr>, Box<Expr>),
    GreaterEquals(Box<Expr>, Box<Expr>),
    Plus(Box<Expr>, Box<Expr>),
    Minus(Box<Expr>, Box<Expr>),
    Multiply(Box<Expr>, Box<Expr>),
    Divide(Box<Expr>, Box<Expr>),
    Modulo(Box<Expr>, Box<Expr>),

    // Member access: obj.prop or obj["prop"]
    Member(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),

    // Function call: func(args)
    Call(Box<Expr>, Vec<Expr>),

    // Ternary: cond ? then : else
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),

    // Method call: obj.method(args)
    MethodCall(Box<Expr>, String, Vec<Expr>),
}

/// Expression parser and evaluator
pub struct ScriptEvaluator {
    // Pre-built expressions for reuse
    filter_expr: Option<Expr>,
    sort_expr: Option<Expr>,
    #[allow(dead_code)]
    // Cache for compiled expressions
    compiled: HashMap<String, Expr>,
}

impl Default for ScriptEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptEvaluator {
    pub fn new() -> Self {
        Self {
            filter_expr: None,
            sort_expr: None,
            compiled: HashMap::new(),
        }
    }

    /// Compile a filter_script expression
    pub fn compile_filter(&mut self, script: &str) -> Result<(), String> {
        let tokens = self.tokenize(script)?;
        let mut pos = 0;
        let expr = self.parse_expression(&mut pos, &tokens)?;
        self.filter_expr = Some(expr);
        Ok(())
    }

    /// Compile a sort_script expression
    pub fn compile_sort(&mut self, script: &str) -> Result<(), String> {
        let tokens = self.tokenize(script)?;
        let mut pos = 0;
        let expr = self.parse_expression(&mut pos, &tokens)?;
        self.sort_expr = Some(expr);
        Ok(())
    }

    /// Evaluate filter_script for a node - returns true if node should be kept
    pub fn evaluate_filter(&self, node: &ProxyNode) -> bool {
        if let Some(ref expr) = self.filter_expr {
            let ctx = NodeContext { node, other: None };
            match self.evaluate(expr, &ctx) {
                JsValue::Bool(b) => b,
                JsValue::Str(s) => !s.is_empty(),
                JsValue::Num(n) => n != 0.0,
                _ => true,
            }
        } else {
            true // No filter means keep all
        }
    }

    /// Evaluate sort_script comparing node_a and node_b
    /// Returns: negative if a < b, positive if a > b, 0 if equal
    pub fn evaluate_sort(&self, node_a: &ProxyNode, node_b: &ProxyNode) -> i32 {
        if let Some(ref expr) = self.sort_expr {
            let ctx = NodeContext {
                node: node_a,
                other: Some(node_b),
            };
            match self.evaluate(expr, &ctx) {
                JsValue::Num(n) => n as i32,
                JsValue::Str(s) => {
                    // For string returns, try to parse as number or compare strings
                    if let Ok(num) = s.parse::<f64>() {
                        num as i32
                    } else {
                        // String comparison fallback - compare lexically
                        s.cmp(&String::new()) as i32
                    }
                }
                JsValue::Bool(b) if b => 1,
                _ => 0,
            }
        } else {
            // Default: compare by name
            node_a.name.to_lowercase().cmp(&node_b.name.to_lowercase()) as i32
        }
    }

    /// Tokenize a script string
    fn tokenize(&self, script: &str) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();
        let mut chars = script.chars().peekable();
        let mut string_char; // assigned on first use in string parsing

        while let Some(&c) = chars.peek() {
            match c {
                ' ' | '\t' | '\n' | '\r' => {
                    chars.next();
                }
                '"' | '\'' => {
                    chars.next();
                    string_char = c;
                    let mut s = String::new();
                    while let Some(&c) = chars.peek() {
                        if c == string_char {
                            chars.next();
                            break;
                        }
                        if c == '\\' {
                            chars.next();
                            if let Some(&esc) = chars.peek() {
                                match esc {
                                    'n' => s.push('\n'),
                                    't' => s.push('\t'),
                                    'r' => s.push('\r'),
                                    '\\' => s.push('\\'),
                                    '"' => s.push('"'),
                                    '\'' => s.push('\''),
                                    'u' => {
                                        chars.next();
                                        let mut hex = String::new();
                                        for _ in 0..4 {
                                            if let Some(&h) = chars.peek() {
                                                hex.push(h);
                                                chars.next();
                                            }
                                        }
                                        if let Ok(cp) = u32::from_str_radix(&hex, 16) {
                                            s.push(char::from_u32(cp).unwrap_or('?'));
                                        }
                                    }
                                    _ => s.push(esc),
                                }
                            }
                        } else {
                            s.push(c);
                            chars.next();
                        }
                    }
                    tokens.push(Token::String(s));
                }
                '0'..='9' | '.' => {
                    let mut num_str = String::new();
                    let mut has_dot = false;
                    while let Some(&c) = chars.peek() {
                        if c.is_numeric() {
                            num_str.push(c);
                            chars.next();
                        } else if c == '.' && !has_dot {
                            has_dot = true;
                            num_str.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if num_str == "." {
                        // lone "." is the dot token, not a number
                        tokens.push(Token::Dot);
                    } else if let Ok(n) = num_str.parse::<f64>() {
                        tokens.push(Token::Number(n));
                    }
                }
                'a'..='z' | 'A'..='Z' | '_' => {
                    let mut ident = String::new();
                    while let Some(&c) = chars.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            ident.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    match ident.as_str() {
                        "true" => tokens.push(Token::Boolean(true)),
                        "false" => tokens.push(Token::Boolean(false)),
                        "null" | "undefined" => tokens.push(Token::Null),
                        "new" => tokens.push(Token::Identifier("new".to_string())),
                        _ => tokens.push(Token::Identifier(ident)),
                    }
                }
                '+' => {
                    tokens.push(Token::Plus);
                    chars.next();
                }
                '-' => {
                    tokens.push(Token::Minus);
                    chars.next();
                }
                '*' => {
                    tokens.push(Token::Multiply);
                    chars.next();
                }
                '/' => {
                    chars.next();
                    if chars.peek() == Some(&'/') {
                        // Line comment - skip to end of line
                        while let Some(&c) = chars.peek() {
                            if c == '\n' {
                                break;
                            }
                            chars.next();
                        }
                    } else {
                        tokens.push(Token::Divide);
                    }
                }
                '%' => {
                    tokens.push(Token::Modulo);
                    chars.next();
                }
                '=' => {
                    chars.next();
                    if chars.peek() == Some(&'=') {
                        chars.next();
                        tokens.push(Token::Equals);
                    } else {
                        // Assignment - treat as comparison
                        tokens.push(Token::Equals);
                    }
                }
                '!' => {
                    chars.next();
                    if chars.peek() == Some(&'=') {
                        chars.next();
                        tokens.push(Token::NotEquals);
                    } else {
                        tokens.push(Token::Not);
                    }
                }
                '<' => {
                    chars.next();
                    if chars.peek() == Some(&'=') {
                        chars.next();
                        tokens.push(Token::LessEquals);
                    } else {
                        tokens.push(Token::LessThan);
                    }
                }
                '>' => {
                    chars.next();
                    if chars.peek() == Some(&'=') {
                        chars.next();
                        tokens.push(Token::GreaterEquals);
                    } else {
                        tokens.push(Token::GreaterThan);
                    }
                }
                '&' => {
                    chars.next();
                    if chars.peek() == Some(&'&') {
                        chars.next();
                        tokens.push(Token::And);
                    } else {
                        // Bitwise and - not supported
                    }
                }
                '|' => {
                    chars.next();
                    if chars.peek() == Some(&'|') {
                        chars.next();
                        tokens.push(Token::Or);
                    } else {
                        // Bitwise or - not supported
                    }
                }
                '(' => {
                    tokens.push(Token::LParen);
                    chars.next();
                }
                ')' => {
                    tokens.push(Token::RParen);
                    chars.next();
                }
                '[' => {
                    tokens.push(Token::LBracket);
                    chars.next();
                }
                ']' => {
                    tokens.push(Token::RBracket);
                    chars.next();
                }
                ',' => {
                    tokens.push(Token::Comma);
                    chars.next();
                }
                '?' => {
                    tokens.push(Token::Semicolon);
                    chars.next();
                }
                ':' => {
                    tokens.push(Token::Colon);
                    chars.next();
                }
                // '.' is handled in the number parsing case above
                // all other chars are skipped
                _ => {
                    chars.next();
                }
            }
        }
        tokens.push(Token::Eof);
        Ok(tokens)
    }

    /// Parse tokens into an expression
    fn parse_expression(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        self.parse_conditional(pos, tokens)
    }

    fn parse_conditional(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let cond = self.parse_or(pos, tokens)?;

        if tokens.get(*pos) == Some(&Token::Semicolon) || tokens.get(*pos) == Some(&Token::Colon) {
            // Ternary: cond ? then : else
            *pos += 1;
            let then_expr = self.parse_or(pos, tokens)?;
            if tokens.get(*pos) == Some(&Token::Colon) {
                *pos += 1;
                let else_expr = self.parse_or(pos, tokens)?;
                return Ok(Expr::Ternary(
                    Box::new(cond),
                    Box::new(then_expr),
                    Box::new(else_expr),
                ));
            }
        }

        Ok(cond)
    }

    fn parse_or(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let mut left = self.parse_and(pos, tokens)?;

        while tokens.get(*pos) == Some(&Token::Or) {
            *pos += 1;
            let right = self.parse_and(pos, tokens)?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_and(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let mut left = self.parse_equality(pos, tokens)?;

        while tokens.get(*pos) == Some(&Token::And) {
            *pos += 1;
            let right = self.parse_equality(pos, tokens)?;
            left = Expr::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_equality(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let mut left = self.parse_comparison(pos, tokens)?;

        loop {
            let op = tokens.get(*pos).cloned();
            match op {
                Some(Token::Equals) => {
                    *pos += 1;
                    let right = self.parse_comparison(pos, tokens)?;
                    left = Expr::Equals(Box::new(left), Box::new(right));
                }
                Some(Token::NotEquals) => {
                    *pos += 1;
                    let right = self.parse_comparison(pos, tokens)?;
                    left = Expr::NotEquals(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }

        Ok(left)
    }

    fn parse_comparison(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let mut left = self.parse_addition(pos, tokens)?;

        loop {
            let op = tokens.get(*pos).cloned();
            match op {
                Some(Token::LessThan) => {
                    *pos += 1;
                    let right = self.parse_addition(pos, tokens)?;
                    left = Expr::LessThan(Box::new(left), Box::new(right));
                }
                Some(Token::GreaterThan) => {
                    *pos += 1;
                    let right = self.parse_addition(pos, tokens)?;
                    left = Expr::GreaterThan(Box::new(left), Box::new(right));
                }
                Some(Token::LessEquals) => {
                    *pos += 1;
                    let right = self.parse_addition(pos, tokens)?;
                    left = Expr::LessEquals(Box::new(left), Box::new(right));
                }
                Some(Token::GreaterEquals) => {
                    *pos += 1;
                    let right = self.parse_addition(pos, tokens)?;
                    left = Expr::GreaterEquals(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }

        Ok(left)
    }

    fn parse_addition(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let mut left = self.parse_multiplication(pos, tokens)?;

        loop {
            let op = tokens.get(*pos).cloned();
            match op {
                Some(Token::Plus) => {
                    *pos += 1;
                    let right = self.parse_multiplication(pos, tokens)?;
                    left = Expr::Plus(Box::new(left), Box::new(right));
                }
                Some(Token::Minus) => {
                    *pos += 1;
                    let right = self.parse_multiplication(pos, tokens)?;
                    left = Expr::Minus(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }

        Ok(left)
    }

    fn parse_multiplication(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let mut left = self.parse_unary(pos, tokens)?;

        loop {
            let op = tokens.get(*pos).cloned();
            match op {
                Some(Token::Multiply) => {
                    *pos += 1;
                    let right = self.parse_unary(pos, tokens)?;
                    left = Expr::Multiply(Box::new(left), Box::new(right));
                }
                Some(Token::Divide) => {
                    *pos += 1;
                    let right = self.parse_unary(pos, tokens)?;
                    left = Expr::Divide(Box::new(left), Box::new(right));
                }
                Some(Token::Modulo) => {
                    *pos += 1;
                    let right = self.parse_unary(pos, tokens)?;
                    left = Expr::Modulo(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }

        Ok(left)
    }

    fn parse_unary(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let op = tokens.get(*pos).cloned();
        match op {
            Some(Token::Not) => {
                *pos += 1;
                let expr = self.parse_unary(pos, tokens)?;
                Ok(Expr::Not(Box::new(expr)))
            }
            Some(Token::Minus) => {
                *pos += 1;
                let expr = self.parse_unary(pos, tokens)?;
                Ok(Expr::Negate(Box::new(expr)))
            }
            _ => self.parse_member_access(pos, tokens),
        }
    }

    fn parse_member_access(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let mut expr = self.parse_primary(pos, tokens)?;

        loop {
            match tokens.get(*pos).cloned() {
                Some(Token::Dot) => {
                    *pos += 1;
                    if let Some(Token::Identifier(prop)) = tokens.get(*pos).cloned() {
                        *pos += 1;
                        // Check if it's a method call
                        if tokens.get(*pos) == Some(&Token::LParen) {
                            let args = self.parse_arguments(pos, tokens)?;
                            expr = Expr::MethodCall(Box::new(expr), prop, args);
                        } else {
                            expr = Expr::Member(Box::new(expr), prop);
                        }
                    }
                }
                Some(Token::LBracket) => {
                    *pos += 1;
                    let index = self.parse_expression(pos, tokens)?;
                    if tokens.get(*pos) == Some(&Token::RBracket) {
                        *pos += 1;
                    }
                    expr = Expr::Index(Box::new(expr), Box::new(index));
                }
                Some(Token::LParen) => {
                    // Function call on previous expression
                    let args = self.parse_arguments(pos, tokens)?;
                    expr = Expr::Call(Box::new(expr), args);
                }
                _ => break,
            }
        }

        Ok(expr)
    }

    fn parse_arguments(&self, pos: &mut usize, tokens: &[Token]) -> Result<Vec<Expr>, String> {
        let mut args = Vec::new();
        if tokens.get(*pos) == Some(&Token::LParen) {
            *pos += 1;
            while tokens.get(*pos) != Some(&Token::Eof) && tokens.get(*pos) != Some(&Token::RParen)
            {
                args.push(self.parse_expression(pos, tokens)?);
                if tokens.get(*pos) == Some(&Token::Comma) {
                    *pos += 1;
                } else {
                    break;
                }
            }
            if tokens.get(*pos) == Some(&Token::RParen) {
                *pos += 1;
            }
        }
        Ok(args)
    }

    fn parse_primary(&self, pos: &mut usize, tokens: &[Token]) -> Result<Expr, String> {
        let token = tokens
            .get(*pos)
            .cloned()
            .ok_or("Unexpected end of expression")?;

        match token {
            Token::String(s) => {
                *pos += 1;
                Ok(Expr::String(s))
            }
            Token::Number(n) => {
                *pos += 1;
                Ok(Expr::Number(n))
            }
            Token::Boolean(b) => {
                *pos += 1;
                Ok(Expr::Boolean(b))
            }
            Token::Null => {
                *pos += 1;
                Ok(Expr::Null)
            }
            Token::Identifier(name) => {
                *pos += 1;
                // Check for function call
                if tokens.get(*pos) == Some(&Token::LParen) {
                    let args = self.parse_arguments(pos, tokens)?;
                    Ok(Expr::Call(Box::new(Expr::Identifier(name)), args))
                } else {
                    Ok(Expr::Identifier(name))
                }
            }
            Token::LParen => {
                *pos += 1;
                let expr = self.parse_expression(pos, tokens)?;
                if tokens.get(*pos) == Some(&Token::RParen) {
                    *pos += 1;
                }
                Ok(expr)
            }
            _ => Err(format!("Unexpected token: {:?}", token)),
        }
    }

    /// Evaluate an expression with the given context
    fn evaluate(&self, expr: &Expr, ctx: &NodeContext) -> JsValue {
        match expr {
            Expr::String(s) => JsValue::Str(s.clone()),
            Expr::Number(n) => JsValue::Num(*n),
            Expr::Boolean(b) => JsValue::Bool(*b),
            Expr::Null => JsValue::Null,

            Expr::Identifier(name) => {
                if name == "other" {
                    // Return a marker value that we'll intercept in Member handling
                    if ctx.other.is_some() {
                        JsValue::Method("__other__".to_string())
                    } else {
                        JsValue::Null
                    }
                } else {
                    // Check if it's a node property
                    let prop_value = ctx.get_property(name);
                    if prop_value != JsValue::Null {
                        prop_value
                    } else {
                        // Try 'other' property
                        ctx.get_other_property(name)
                    }
                }
            }

            Expr::Not(e) => match self.evaluate(e, ctx) {
                JsValue::Bool(b) => JsValue::Bool(!b),
                JsValue::Str(s) => JsValue::Bool(s.is_empty()),
                JsValue::Num(n) => JsValue::Bool(n == 0.0),
                JsValue::Null => JsValue::Bool(true),
                JsValue::Array(arr) => JsValue::Bool(arr.is_empty()),
                JsValue::Method(_) => JsValue::Bool(false),
            },

            Expr::Negate(e) => match self.evaluate(e, ctx) {
                JsValue::Num(n) => JsValue::Num(-n),
                _ => JsValue::Null,
            },

            Expr::And(a, b) => {
                let a_val = self.evaluate(a, ctx);
                match a_val {
                    JsValue::Bool(false) | JsValue::Null | JsValue::Num(0.0) => {
                        JsValue::Bool(false)
                    }
                    _ => JsValue::Bool(self.evaluate(b, ctx).is_truthy()),
                }
            }

            Expr::Or(a, b) => {
                let a_val = self.evaluate(a, ctx);
                match a_val {
                    JsValue::Bool(false) | JsValue::Null | JsValue::Num(0.0) => {
                        self.evaluate(b, ctx)
                    }
                    _ => a_val,
                }
            }

            Expr::Equals(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                JsValue::Bool(a_val.equals(&b_val))
            }

            Expr::NotEquals(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                JsValue::Bool(!a_val.equals(&b_val))
            }

            Expr::LessThan(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                JsValue::Bool(a_val.less_than(&b_val))
            }

            Expr::GreaterThan(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                JsValue::Bool(b_val.less_than(&a_val))
            }

            Expr::LessEquals(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                JsValue::Bool(a_val.equals(&b_val) || a_val.less_than(&b_val))
            }

            Expr::GreaterEquals(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                JsValue::Bool(a_val.equals(&b_val) || b_val.less_than(&a_val))
            }

            Expr::Plus(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                a_val.add(&b_val)
            }

            Expr::Minus(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                match (a_val, b_val) {
                    (JsValue::Num(na), JsValue::Num(nb)) => JsValue::Num(na - nb),
                    _ => JsValue::Null,
                }
            }

            Expr::Multiply(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                match (a_val, b_val) {
                    (JsValue::Num(na), JsValue::Num(nb)) => JsValue::Num(na * nb),
                    _ => JsValue::Null,
                }
            }

            Expr::Divide(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                match (a_val, b_val) {
                    (JsValue::Num(na), JsValue::Num(nb)) if nb != 0.0 => JsValue::Num(na / nb),
                    _ => JsValue::Null,
                }
            }

            Expr::Modulo(a, b) => {
                let a_val = self.evaluate(a, ctx);
                let b_val = self.evaluate(b, ctx);
                match (a_val, b_val) {
                    (JsValue::Num(na), JsValue::Num(nb)) if nb != 0.0 => JsValue::Num(na % nb),
                    _ => JsValue::Null,
                }
            }

            Expr::Member(obj, prop) => {
                let obj_val = self.evaluate(obj, ctx);
                // Check for "other" node marker
                if let JsValue::Method(ref m) = obj_val {
                    if m == "__other__" {
                        // Access property on ctx.other
                        if let Some(other) = ctx.other {
                            let temp_ctx = NodeContext {
                                node: other,
                                other: None,
                            };
                            let result = temp_ctx.get_property(prop);
                            return result;
                        }
                        return JsValue::Null;
                    }
                }
                self.get_member_value(&obj_val, prop)
            }

            Expr::Index(obj, index) => {
                let obj_val = self.evaluate(obj, ctx);
                // Check for "other" node marker
                if let JsValue::Method(ref m) = obj_val {
                    if m == "__other__" {
                        // other[property_name] is not commonly used but handle it anyway
                        return JsValue::Null;
                    }
                }
                let index_val = self.evaluate(index, ctx);
                if let JsValue::Num(n) = index_val {
                    if let JsValue::Str(ref s) = obj_val {
                        let idx = n as usize;
                        if let Some(c) = s.chars().nth(idx) {
                            return JsValue::Str(c.to_string());
                        }
                    } else if let JsValue::Array(ref arr) = obj_val {
                        let idx = n as usize;
                        if idx < arr.len() {
                            return arr[idx].clone();
                        }
                    }
                }
                JsValue::Null
            }

            Expr::Call(func, args) => self.evaluate_call(&self.evaluate(func, ctx), args, ctx),

            Expr::MethodCall(obj, method, args) => {
                let obj_val = self.evaluate(obj, ctx);

                self.evaluate_method(&obj_val, method, args, ctx)
            }

            Expr::Ternary(cond, then_expr, else_expr) => {
                let cond_val = self.evaluate(cond, ctx);
                if cond_val.is_truthy() {
                    self.evaluate(then_expr, ctx)
                } else {
                    self.evaluate(else_expr, ctx)
                }
            }
        }
    }

    fn get_member_value(&self, obj: &JsValue, prop: &str) -> JsValue {
        match obj {
            JsValue::Str(s) => match prop {
                "length" => JsValue::Num(s.chars().count() as f64),
                "includes" => JsValue::Method("includes".to_string()),
                "startsWith" => JsValue::Method("startsWith".to_string()),
                "endsWith" => JsValue::Method("endsWith".to_string()),
                "indexOf" => JsValue::Method("indexOf".to_string()),
                "toLowerCase" => JsValue::Method("toLowerCase".to_string()),
                "toUpperCase" => JsValue::Method("toUpperCase".to_string()),
                "trim" => JsValue::Method("trim".to_string()),
                "split" => JsValue::Method("split".to_string()),
                "replace" => JsValue::Method("replace".to_string()),
                "match" => JsValue::Method("match".to_string()),
                "charAt" => JsValue::Method("charAt".to_string()),
                "charCodeAt" => JsValue::Method("charCodeAt".to_string()),
                "substring" => JsValue::Method("substring".to_string()),
                "substr" => JsValue::Method("substr".to_string()),
                "localeCompare" => JsValue::Method("localeCompare".to_string()),
                _ => JsValue::Null,
            },
            JsValue::Array(arr) => match prop {
                "length" => JsValue::Num(arr.len() as f64),
                _ => JsValue::Null,
            },
            JsValue::Null => JsValue::Null,
            _ => JsValue::Null,
        }
    }

    fn evaluate_call(&self, func: &JsValue, args: &[Expr], ctx: &NodeContext) -> JsValue {
        if let JsValue::Str(ref s) = func {
            // Built-in string methods that take arguments
            if let JsValue::Str(ref str_val) = ctx.get_property("_str") {
                match s.as_str() {
                    "includes" => {
                        if !args.is_empty() {
                            let search_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Str(ref search) = search_val {
                                return JsValue::Bool(str_val.contains(search));
                            }
                        }
                    }
                    "startsWith" => {
                        if !args.is_empty() {
                            let prefix_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Str(ref prefix) = prefix_val {
                                return JsValue::Bool(str_val.starts_with(prefix));
                            }
                        }
                    }
                    "endsWith" => {
                        if !args.is_empty() {
                            let suffix_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Str(ref suffix) = suffix_val {
                                return JsValue::Bool(str_val.ends_with(suffix));
                            }
                        }
                    }
                    "indexOf" => {
                        if !args.is_empty() {
                            let search_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Str(ref search) = search_val {
                                return JsValue::Num(
                                    str_val.find(search).map(|i| i as f64).unwrap_or(-1.0),
                                );
                            }
                        }
                    }
                    "toLowerCase" => {
                        return JsValue::Str(str_val.to_lowercase());
                    }
                    "toUpperCase" => {
                        return JsValue::Str(str_val.to_uppercase());
                    }
                    "trim" => {
                        return JsValue::Str(str_val.trim().to_string());
                    }
                    "charAt" => {
                        if !args.is_empty() {
                            let idx_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Num(n) = idx_val {
                                let idx = n as usize;
                                if let Some(c) = str_val.chars().nth(idx) {
                                    return JsValue::Str(c.to_string());
                                }
                            }
                        }
                    }
                    "charCodeAt" => {
                        if !args.is_empty() {
                            let idx_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Num(n) = idx_val {
                                let idx = n as usize;
                                if let Some(c) = str_val.chars().nth(idx) {
                                    return JsValue::Num(c as u32 as f64);
                                }
                            }
                        }
                    }
                    "substring" | "substr" => {
                        if args.len() >= 2 {
                            let start_val = self.evaluate(&args[0], ctx);
                            let end_val = self.evaluate(&args[1], ctx);
                            if let (JsValue::Num(start), JsValue::Num(end)) = (start_val, end_val) {
                                return JsValue::Str(js_substring(
                                    str_val,
                                    start as usize,
                                    end as usize,
                                ));
                            }
                        }
                    }
                    "split" => {
                        if !args.is_empty() {
                            let sep_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Str(ref sep) = sep_val {
                                if sep.is_empty() {
                                    return JsValue::Array(
                                        str_val
                                            .chars()
                                            .map(|c| JsValue::Str(c.to_string()))
                                            .collect(),
                                    );
                                } else {
                                    return JsValue::Array(
                                        str_val
                                            .split(sep)
                                            .map(|s| JsValue::Str(s.to_string()))
                                            .collect(),
                                    );
                                }
                            }
                        }
                    }
                    "replace" => {
                        if args.len() >= 2 {
                            let find_val = self.evaluate(&args[0], ctx);
                            let repl_val = self.evaluate(&args[1], ctx);
                            if let (JsValue::Str(ref find), JsValue::Str(ref repl)) =
                                (find_val, repl_val)
                            {
                                if let Some(pos) = str_val.find(find) {
                                    let mut result = str_val[..pos].to_string();
                                    result.push_str(repl);
                                    result.push_str(&str_val[pos + find.len()..]);
                                    return JsValue::Str(result);
                                }
                            }
                        }
                    }
                    "match" => {
                        if !args.is_empty() {
                            let pattern_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Str(ref pattern) = pattern_val {
                                // Simple regex matching
                                if let Ok(re) = regex::Regex::new(pattern) {
                                    if re.is_match(str_val) {
                                        return JsValue::Bool(true);
                                    }
                                }
                            }
                        }
                        return JsValue::Bool(false);
                    }
                    "localeCompare" => {
                        // Returns: -1 if str < other, 0 if equal, 1 if str > other
                        if !args.is_empty() {
                            let other_val = self.evaluate(&args[0], ctx);
                            if let JsValue::Str(ref other) = other_val {
                                return JsValue::Num(
                                    str_val.to_lowercase().cmp(&other.to_lowercase()) as i32 as f64,
                                );
                            }
                        }
                        return JsValue::Num(0.0);
                    }
                    _ => {}
                }
            }
        }
        JsValue::Null
    }

    fn evaluate_method(
        &self,
        obj: &JsValue,
        method: &str,
        args: &[Expr],
        ctx: &NodeContext,
    ) -> JsValue {
        // Handle method references - we need to evaluate the object to get its string value
        let str_value = if let JsValue::Method(ref _method_name) = obj {
            // This shouldn't happen if we handle it in the Call case, but just in case
            return JsValue::Null;
        } else if let JsValue::Str(ref s) = obj {
            s.clone()
        } else {
            return JsValue::Null;
        };

        match method {
            "includes" => {
                if !args.is_empty() {
                    let search_val = self.evaluate(&args[0], ctx);
                    if let JsValue::Str(ref search) = search_val {
                        return JsValue::Bool(str_value.contains(search));
                    }
                }
            }
            "startsWith" => {
                if !args.is_empty() {
                    let prefix_val = self.evaluate(&args[0], ctx);
                    if let JsValue::Str(ref prefix) = prefix_val {
                        return JsValue::Bool(str_value.starts_with(prefix));
                    }
                }
            }
            "endsWith" => {
                if !args.is_empty() {
                    let suffix_val = self.evaluate(&args[0], ctx);
                    if let JsValue::Str(ref suffix) = suffix_val {
                        return JsValue::Bool(str_value.ends_with(suffix));
                    }
                }
            }
            "toLowerCase" => {
                return JsValue::Str(str_value.to_lowercase());
            }
            "toUpperCase" => {
                return JsValue::Str(str_value.to_uppercase());
            }
            "trim" => {
                return JsValue::Str(str_value.trim().to_string());
            }
            "charAt" => {
                if !args.is_empty() {
                    let idx_val = self.evaluate(&args[0], ctx);
                    if let JsValue::Num(n) = idx_val {
                        let idx = n as usize;
                        if let Some(c) = str_value.chars().nth(idx) {
                            return JsValue::Str(c.to_string());
                        }
                    }
                }
            }
            "indexOf" => {
                if !args.is_empty() {
                    let search_val = self.evaluate(&args[0], ctx);
                    if let JsValue::Str(ref search) = search_val {
                        return JsValue::Num(
                            str_value.find(search).map(|i| i as f64).unwrap_or(-1.0),
                        );
                    }
                }
            }
            "substring" | "substr" => {
                if args.len() >= 2 {
                    let start_val = self.evaluate(&args[0], ctx);
                    let end_val = self.evaluate(&args[1], ctx);
                    if let (JsValue::Num(start), JsValue::Num(end)) = (start_val, end_val) {
                        return JsValue::Str(js_substring(
                            &str_value,
                            start as usize,
                            end as usize,
                        ));
                    }
                }
            }
            "split" => {
                if !args.is_empty() {
                    let sep_val = self.evaluate(&args[0], ctx);
                    if let JsValue::Str(ref sep) = sep_val {
                        if sep.is_empty() {
                            return JsValue::Array(
                                str_value
                                    .chars()
                                    .map(|c| JsValue::Str(c.to_string()))
                                    .collect(),
                            );
                        } else {
                            return JsValue::Array(
                                str_value
                                    .split(sep)
                                    .map(|s| JsValue::Str(s.to_string()))
                                    .collect(),
                            );
                        }
                    }
                }
            }
            "replace" => {
                if args.len() >= 2 {
                    let find_val = self.evaluate(&args[0], ctx);
                    let repl_val = self.evaluate(&args[1], ctx);
                    if let (JsValue::Str(ref find), JsValue::Str(ref repl)) = (find_val, repl_val) {
                        if let Some(pos) = str_value.find(find) {
                            let mut result = str_value[..pos].to_string();
                            result.push_str(repl);
                            result.push_str(&str_value[pos + find.len()..]);
                            return JsValue::Str(result);
                        }
                    }
                }
            }
            "match" => {
                if !args.is_empty() {
                    let pattern_val = self.evaluate(&args[0], ctx);
                    if let JsValue::Str(ref pattern) = pattern_val {
                        if let Ok(re) = regex::Regex::new(pattern) {
                            if re.is_match(&str_value) {
                                return JsValue::Bool(true);
                            }
                        }
                    }
                }
                return JsValue::Bool(false);
            }
            "localeCompare" => {
                // Returns: -1 if str < other, 0 if equal, 1 if str > other
                if !args.is_empty() {
                    let other_val = self.evaluate(&args[0], ctx);
                    if let JsValue::Str(ref other) = other_val {
                        let result =
                            str_value.to_lowercase().cmp(&other.to_lowercase()) as i32 as f64;
                        return JsValue::Num(result);
                    }
                }
                return JsValue::Num(0.0);
            }
            _ => {}
        }
        JsValue::Null
    }
}

impl JsValue {
    fn is_truthy(&self) -> bool {
        match self {
            JsValue::Bool(b) => *b,
            JsValue::Null => false,
            JsValue::Num(n) => *n != 0.0,
            JsValue::Str(s) => !s.is_empty(),
            JsValue::Array(arr) => !arr.is_empty(),
            JsValue::Method(_) => true,
        }
    }

    fn equals(&self, other: &JsValue) -> bool {
        match (self, other) {
            (JsValue::Str(a), JsValue::Str(b)) => a == b,
            (JsValue::Num(a), JsValue::Num(b)) => (a - b).abs() < f64::EPSILON,
            (JsValue::Bool(a), JsValue::Bool(b)) => a == b,
            (JsValue::Null, JsValue::Null) => true,
            (JsValue::Method(a), JsValue::Method(b)) => a == b,
            (JsValue::Num(n), JsValue::Bool(b)) | (JsValue::Bool(b), JsValue::Num(n)) => {
                (*n != 0.0) == *b
            }
            (JsValue::Str(s), JsValue::Num(n)) | (JsValue::Num(n), JsValue::Str(s)) => {
                if let Ok(parsed) = s.parse::<f64>() {
                    (parsed - n).abs() < f64::EPSILON
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn less_than(&self, other: &JsValue) -> bool {
        match (self, other) {
            (JsValue::Num(a), JsValue::Num(b)) => a < b,
            (JsValue::Str(a), JsValue::Str(b)) => a.to_lowercase() < b.to_lowercase(),
            _ => false,
        }
    }

    fn add(&self, other: &JsValue) -> JsValue {
        match (self, other) {
            (JsValue::Str(a), JsValue::Str(b)) => JsValue::Str(format!("{}{}", a, b)),
            (JsValue::Num(a), JsValue::Num(b)) => JsValue::Num(a + b),
            (JsValue::Str(a), _) => JsValue::Str(format!("{}{}", a, other)),
            (_, JsValue::Str(b)) => JsValue::Str(format!("{}{}", self, b)),
            _ => JsValue::Null,
        }
    }
}

/// Apply filter_script to filter nodes
pub fn apply_filter_script(nodes: &[ProxyNode], script: &str) -> Result<Vec<ProxyNode>, String> {
    let mut evaluator = ScriptEvaluator::new();
    evaluator.compile_filter(script)?;

    let filtered: Vec<ProxyNode> = nodes
        .iter()
        .filter(|node| evaluator.evaluate_filter(node))
        .cloned()
        .collect();

    Ok(filtered)
}

/// Apply sort_script to sort nodes
pub fn apply_sort_script(nodes: &mut [ProxyNode], script: &str) -> Result<(), String> {
    let mut evaluator = ScriptEvaluator::new();
    evaluator.compile_sort(script)?;

    // Use stable sort to preserve original order for equal elements
    let cmp = |a: &ProxyNode, b: &ProxyNode| evaluator.evaluate_sort(a, b).cmp(&0);

    // Use sort_by with the evaluator
    nodes.sort_by(cmp);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subconverter::ProxyProtocol;

    fn create_test_node(name: &str, server: &str, port: u16, protocol: ProxyProtocol) -> ProxyNode {
        ProxyNode {
            name: name.to_string(),
            server: server.to_string(),
            port,
            protocol,
            extra: Default::default(),
        }
    }

    #[test]
    fn test_substring_edge_cases_do_not_panic() {
        // JS substring semantics: swap when start > end, clamp to char
        // count — never panic on multibyte names or reversed indices.
        assert_eq!(js_substring("hello", 5, 2), "llo"); // swapped
        assert_eq!(js_substring("hello", 0, 99), "hello"); // clamped end
        assert_eq!(js_substring("香港HK01", 8, 9), ""); // byte-range > chars
        assert_eq!(js_substring("香港HK01", 2, 4), "HK"); // char-indexed
        assert_eq!(js_substring("", 0, 5), "");
    }

    #[test]
    fn test_string_methods_on_multibyte_names_do_not_panic() {
        // Regression: charAt/charCodeAt/indexing used to check the BYTE
        // length but index CHARS — any index between char count and byte
        // length panicked on CJK/emoji names (NFR-2.2).
        let cjk = "日本語ノード🇯🇵";
        let nodes = vec![create_test_node(cjk, "1.2.3.4", 443, ProxyProtocol::Trojan)];
        for script in [
            "name.charAt(5) != 'x'",
            "name.charCodeAt(6) > 0",
            "name[7] != 'y'",
            "name.substring(3, 8) != 'z'",
        ] {
            let result = apply_filter_script(&nodes, script);
            assert!(result.is_ok(), "script panicked or failed: {script}");
        }
    }

    #[test]
    fn test_filter_script_simple_include() {
        let nodes = vec![
            create_test_node("US Node 1", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("HK Node 1", "5.6.7.8", 443, ProxyProtocol::Trojan),
            create_test_node("JP Node 1", "9.10.11.12", 443, ProxyProtocol::Trojan),
        ];

        let result = apply_filter_script(&nodes, "name.includes(\"US\")").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "US Node 1");
    }

    #[test]
    fn test_filter_script_or() {
        let nodes = vec![
            create_test_node("US Node", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("HK Node", "5.6.7.8", 443, ProxyProtocol::Trojan),
            create_test_node("JP Node", "9.10.11.12", 443, ProxyProtocol::Trojan),
        ];

        let result =
            apply_filter_script(&nodes, "name.includes(\"US\") || name.includes(\"HK\")").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_script_and() {
        let nodes = vec![
            create_test_node("US Node Fast", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("US Node Slow", "5.6.7.8", 443, ProxyProtocol::Trojan),
            create_test_node("HK Node Fast", "9.10.11.12", 443, ProxyProtocol::Trojan),
        ];

        let result =
            apply_filter_script(&nodes, "name.includes(\"US\") && name.includes(\"Fast\")")
                .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "US Node Fast");
    }

    #[test]
    fn test_filter_script_not() {
        let nodes = vec![
            create_test_node("US Node", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("流量提醒", "5.6.7.8", 443, ProxyProtocol::Trojan),
            create_test_node("JP Node", "9.10.11.12", 443, ProxyProtocol::Trojan),
        ];

        let result = apply_filter_script(&nodes, "!name.includes(\"流量\")").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_script_starts_with() {
        let nodes = vec![
            create_test_node("🇺🇸 US Node", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("🇭🇰 HK Node", "5.6.7.8", 443, ProxyProtocol::Trojan),
        ];

        let result = apply_filter_script(&nodes, "name.startsWith(\"🇺🇸\")").unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_filter_script_protocol() {
        let nodes = vec![
            create_test_node("SS Node", "1.2.3.4", 443, ProxyProtocol::Shadowsocks),
            create_test_node("Trojan Node", "5.6.7.8", 443, ProxyProtocol::Trojan),
            create_test_node("VMess Node", "9.10.11.12", 443, ProxyProtocol::VMess),
        ];

        let result = apply_filter_script(&nodes, "protocol == \"trojan\"").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "Trojan Node");
    }

    #[test]
    fn test_filter_script_port() {
        let nodes = vec![
            create_test_node("Node 1", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("Node 2", "5.6.7.8", 8080, ProxyProtocol::Trojan),
        ];

        let result = apply_filter_script(&nodes, "port > 5000").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].port, 8080);
    }

    #[test]
    fn test_sort_script_name() {
        let mut nodes = vec![
            create_test_node("Zebra", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("Apple", "5.6.7.8", 443, ProxyProtocol::Trojan),
            create_test_node("Mango", "9.10.11.12", 443, ProxyProtocol::Trojan),
        ];

        apply_sort_script(&mut nodes, "name.localeCompare(other.name)").unwrap();

        assert_eq!(nodes[0].name, "Apple");
        assert_eq!(nodes[1].name, "Mango");
        assert_eq!(nodes[2].name, "Zebra");
    }

    #[test]
    fn test_sort_script_reverse() {
        let mut nodes = vec![
            create_test_node("Apple", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("Mango", "5.6.7.8", 443, ProxyProtocol::Trojan),
        ];

        apply_sort_script(&mut nodes, "other.name.localeCompare(name)").unwrap();

        assert_eq!(nodes[0].name, "Mango");
        assert_eq!(nodes[1].name, "Apple");
    }

    #[test]
    fn test_sort_script_port() {
        let mut nodes = vec![
            create_test_node("Node A", "1.2.3.4", 8080, ProxyProtocol::Trojan),
            create_test_node("Node B", "5.6.7.8", 443, ProxyProtocol::Trojan),
            create_test_node("Node C", "9.10.11.12", 9000, ProxyProtocol::Trojan),
        ];

        // Sort by port ascending
        apply_sort_script(&mut nodes, "port - other.port").unwrap();

        assert_eq!(nodes[0].port, 443);
        assert_eq!(nodes[1].port, 8080);
        assert_eq!(nodes[2].port, 9000);
    }

    #[test]
    fn test_filter_script_empty_result() {
        let nodes = vec![create_test_node(
            "US Node",
            "1.2.3.4",
            443,
            ProxyProtocol::Trojan,
        )];

        let result = apply_filter_script(&nodes, "name.includes(\"XX\")").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_script_emoji() {
        let nodes = vec![
            create_test_node("🇺🇸 美国高速节点", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("🇭🇰 香港节点", "5.6.7.8", 443, ProxyProtocol::Trojan),
        ];

        let result = apply_filter_script(&nodes, "name.includes(\"🇺🇸\")").unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].name.contains("美国"));
    }

    #[test]
    fn test_js_value_display() {
        assert_eq!(JsValue::Str("hello".to_string()).to_string(), "\"hello\"");
        assert_eq!(JsValue::Num(42.0).to_string(), "42");
        assert_eq!(JsValue::Bool(true).to_string(), "true");
        assert_eq!(JsValue::Null.to_string(), "null");
    }

    #[test]
    fn test_filter_script_complex_expression() {
        let nodes = vec![
            create_test_node("🇺🇸 US Trojan 443", "1.2.3.4", 443, ProxyProtocol::Trojan),
            create_test_node("🇺🇸 US SS 443", "1.2.3.4", 443, ProxyProtocol::Shadowsocks),
            create_test_node("🇭🇰 HK Trojan 443", "5.6.7.8", 443, ProxyProtocol::Trojan),
            create_test_node("🇯🇵 JP VMess 80", "9.10.11.12", 80, ProxyProtocol::VMess),
        ];

        // Filter: US or HK, and Trojan
        let result = apply_filter_script(
            &nodes,
            "(name.includes(\"US\") || name.includes(\"HK\")) && protocol == \"trojan\"",
        )
        .unwrap();
        assert_eq!(result.len(), 2);
    }
}
