use std::{collections::HashMap, fmt::Display};

use super::Token;

#[derive(Debug, Clone, Default)]
pub struct MetaExpression {
    pub tokens: Vec<TokenDepth>,
    depth_range: HashMap<u32, DepthRange>,
    depth: u32,
}

#[derive(Debug, Clone)]
pub struct TokenDepth {
    token: Token,
    depth: u32,
    prefix: Vec<Token>,
}

#[derive(Debug, Clone, Default)]
struct DepthRange {
    start: usize,
    end: usize,
    expr_end: Option<(usize, bool)>,
    logic_end: bool,
}

impl MetaExpression {
    pub fn from_meta(expr: &str) -> Self {
        let mut meta = MetaExpression::default();
        let mut seen_comp = false;
        let mut buf = String::new();
        let mut iter = expr.chars().peekable();

        while let Some(ch) = iter.next() {
            match ch {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '_' => {
                    buf.push(ch);
                }
                _ => {
                    if !buf.is_empty() {
                        let token = Token::from(buf);
                        buf = String::new();
                        if !seen_comp
                            && matches!(
                                iter.clone()
                                    .find(|t| { ['&', '|', '>', '<', '='].contains(t) }),
                                None | Some('&' | '|')
                            )
                        {
                            meta.push(token);
                            meta.push(Token::Gt);
                            meta.push(Token::Number(0));
                            seen_comp = true;
                        } else {
                            meta.push(token);
                        }
                    }

                    match ch {
                        '&' => {
                            seen_comp = false;
                            if matches!(iter.next(), Some('&')) {
                                meta.push(Token::And);
                            } else {
                                eprintln!("Warning: Single & in meta expression {expr}",);
                            }
                        }
                        '|' => {
                            seen_comp = false;
                            if matches!(iter.next(), Some('|')) {
                                meta.push(Token::Or);
                            } else {
                                eprintln!("Warning: Single | in meta expression {expr}",);
                            }
                        }
                        '!' => {
                            seen_comp = false;
                            meta.push(Token::Not)
                        }
                        '=' => {
                            seen_comp = true;
                            meta.push(match iter.next() {
                                Some('=') => Token::Eq,
                                Some('>') => Token::Ge,
                                Some('<') => Token::Le,
                                _ => {
                                    eprintln!("Warning: Single = in meta expression {expr}",);
                                    Token::Eq
                                }
                            });
                        }
                        '>' => {
                            seen_comp = true;
                            meta.push(match iter.peek() {
                                Some('=') => {
                                    iter.next();
                                    Token::Ge
                                }
                                _ => Token::Gt,
                            })
                        }
                        '<' => {
                            seen_comp = true;
                            meta.push(match iter.peek() {
                                Some('=') => {
                                    iter.next();
                                    Token::Le
                                }
                                _ => Token::Lt,
                            })
                        }
                        '(' => meta.push(Token::OpenParen),
                        ')' => {
                            if meta.depth == 0 {
                                eprintln!(
                                    "Warning: Unmatched close parenthesis in meta expression {expr}"
                                );
                            }

                            meta.push(Token::CloseParen)
                        }
                        '+' => meta.push(Token::Add),
                        '*' => meta.push(Token::Multiply),
                        '/' => meta.push(Token::Divide),
                        ' ' => {}
                        _ => {
                            eprintln!("Warning: Invalid character {ch} in meta expression {expr}");
                            break;
                        }
                    }
                }
            }
        }

        if meta.depth > 0 {
            eprintln!("Warning: Unmatched open parenthesis in meta expression {expr}");
        }

        if !buf.is_empty() {
            meta.push(Token::from(buf));
            if !seen_comp {
                meta.push(Token::Gt);
                meta.push(Token::Number(0));
            }
        }

        meta.finalize();
        meta
    }

    fn push(&mut self, token: Token) {
        let pos = self.tokens.len();
        let depth_range = self
            .depth_range
            .entry(self.depth)
            .or_insert_with(|| DepthRange {
                start: pos,
                end: pos,
                ..Default::default()
            });
        depth_range.end = pos;
        let mut depth = self.depth;
        let mut prefix = vec![];

        match &token {
            Token::OpenParen => {
                if let Some((pos, true)) = depth_range.expr_end {
                    depth_range.expr_end = Some((pos, false));
                }
                self.depth += 1;
            }
            Token::CloseParen => {
                if let Some((pos, is_static)) = depth_range.expr_end.take() {
                    self.tokens[pos + 2]
                        .prefix
                        .push(Token::BeginExpression(is_static));
                    prefix.push(Token::EndExpression(is_static));
                }
                if depth_range.logic_end {
                    prefix.push(Token::CloseParen);
                }
                self.depth = self.depth.saturating_sub(1);
                depth = self.depth;
            }
            Token::Or | Token::And => {
                let start_prefix = &mut self.tokens[depth_range.start].prefix;
                if !start_prefix.contains(&Token::And) && !start_prefix.contains(&Token::Or) {
                    start_prefix.insert(0, token.clone());
                }
                depth_range.logic_end = true;
                if let Some((pos, is_static)) = depth_range.expr_end.take() {
                    self.tokens[pos + 2]
                        .prefix
                        .push(Token::BeginExpression(is_static));
                    prefix.push(Token::EndExpression(is_static));
                }
            }
            Token::Lt | Token::Gt | Token::Eq | Token::Le | Token::Ge => {
                let mut is_static = true;
                let mut start_pos = usize::MAX;
                for (pos, token) in self.tokens.iter().enumerate().rev() {
                    if token.depth >= depth {
                        start_pos = pos;
                        match &token.token {
                            Token::And | Token::Or | Token::Not => {
                                start_pos += 1;
                                break;
                            }
                            Token::OpenParen
                            | Token::CloseParen
                            | Token::Add
                            | Token::Multiply
                            | Token::Divide
                            | Token::Tag(_) => {
                                is_static = false;
                            }
                            _ => {}
                        }
                    } else {
                        break;
                    }
                }
                if start_pos != usize::MAX {
                    self.tokens.push(TokenDepth {
                        token: Token::EndExpression(is_static),
                        depth,
                        prefix: vec![],
                    });
                    self.tokens[start_pos].prefix =
                        vec![token.clone(), Token::BeginExpression(is_static)];
                    depth_range.expr_end = Some((pos, true));
                }
            }
            Token::Tag(_) | Token::Add | Token::Multiply | Token::Divide => {
                if let Some((pos, true)) = depth_range.expr_end {
                    depth_range.expr_end = Some((pos, false));
                }
            }
            _ => {}
        }
        self.tokens.push(TokenDepth {
            token,
            depth,
            prefix,
        })
    }

    fn finalize(&mut self) {
        if let Some(depth_range) = self.depth_range.get(&self.depth) {
            if let Some((pos, is_static)) = depth_range.expr_end {
                self.tokens[pos + 2]
                    .prefix
                    .push(Token::BeginExpression(is_static));
                self.tokens.push(TokenDepth {
                    token: Token::EndExpression(is_static),
                    depth: self.depth,
                    prefix: vec![],
                });
            }
            if depth_range.logic_end {
                self.tokens.push(TokenDepth {
                    token: Token::CloseParen,
                    depth: self.depth,
                    prefix: vec![],
                });
            }
        }
    }
}

impl From<String> for Token {
    fn from(value: String) -> Self {
        if let Ok(value) = value.parse() {
            Token::Number(value)
        } else {
            Token::Tag(value)
        }
    }
}

impl Display for MetaExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("if ")?;

        for token in &self.tokens {
            for token in &token.prefix {
                token.fmt(f)?;
            }

            match &token.token {
                Token::And | Token::Or => f.write_str(", "),
                Token::Gt | Token::Lt | Token::Eq | Token::Ge | Token::Le => f.write_str(" "),
                _ => token.token.fmt(f),
            }?;
        }

        Ok(())
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Tag(t) => t.fmt(f),
            Token::Number(n) => n.fmt(f),
            Token::And => f.write_str("allof("),
            Token::Or => f.write_str("anyof("),
            Token::Not => f.write_str("not "),
            Token::Lt | Token::Eq | Token::Ge | Token::Le | Token::Gt => {
                f.write_str("string :")?;
                match self {
                    Token::Eq => f.write_str("eq")?,
                    Token::Gt => f.write_str("gt")?,
                    Token::Lt => f.write_str("lt")?,
                    Token::Ge => f.write_str("ge")?,
                    Token::Le => f.write_str("gt")?,
                    _ => unreachable!(),
                }
                f.write_str(" ")
            }

            Token::OpenParen => f.write_str("("),
            Token::CloseParen => f.write_str(")"),
            Token::Add => f.write_str(" + "),
            Token::Multiply => f.write_str(" * "),
            Token::Divide => f.write_str(" / "),
            Token::BeginExpression(is_static) => {
                if *is_static {
                    f.write_str("\"")
                } else {
                    f.write_str("\"${")
                }
            }
            Token::EndExpression(is_static) => {
                if *is_static {
                    f.write_str("\"")
                } else {
                    f.write_str("}\"")
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::MetaExpression;

    #[test]
    fn parse_meta() {
        for (expr, expected) in [
            /*(
                concat!(
                    "( ! HTML_IMAGE_ONLY_16 ) && ",
                    "( __LOWER_E > 20 ) && ",
                    "( __E_LIKE_LETTER > ( (__LOWER_E * 14 ) / 10) ) && ",
                    "( __E_LIKE_LETTER < ( 10 * __LOWER_E ) )"
                ),
                "",
            ),
            ("(__DRUGS_ERECTILE1 || __DRUGS_ERECTILE2)", ""),
            ("(__HELO_DYNAMIC_IPADDR && !HELO_STATIC_HOST)", ""),
            ("__ML2 || __ML4", ""),
            ("(__AT_HOTMAIL_MSGID && (!__FROM_HOTMAIL_COM && !__FROM_MSN_COM && !__FROM_YAHOO_COM))", ""),
            ("(0)", ""),
            ("RAZOR2_CHECK + DCC_CHECK + PYZOR_CHECK > 1", ""),*/
            ("__HAS_MSGID && !(__SANE_MSGID || __MSGID_COMMENT)", ""),
            ("!__CTYPE_HTML && __X_MAILER_APPLEMAIL && (__MSGID_APPLEMAIL || __MIME_VERSION_APPLEMAIL)", ""),
            ("((__AUTO_GEN_MS||__AUTO_GEN_3||__AUTO_GEN_4) && !__XM_VBULLETIN && !__X_CRON_ENV)", ""),

        ] {
            let meta = MetaExpression::from_meta(expr);
            //println!("{:#?}", meta.tokens);
            let result = meta.to_string();

            //println!("{}", expected);
            println!("{}", result);

            /*assert_eq!(
                result,
                expected,
                "failed for {expr}"
            );*/
        }
    }
}
