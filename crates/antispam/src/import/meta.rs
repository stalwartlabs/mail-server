use std::{collections::HashMap, fmt::Display, iter::Peekable, str::Chars};

use super::{Comparator, Logical, Operation, Token};

// Parse a meta expression into a list of tokens that can be easily
// converted into a Sieve test.
// The parser is not very robust but works on all SpamAssassin meta expressions.
// It might be a good idea in the future to instead build a parse tree and
// then convert that into a Sieve expression.

#[derive(Debug, Clone, Default)]
pub struct MetaExpression {
    pub tokens: Vec<TokenDepth>,
    depth_range: HashMap<u32, DepthRange>,
    depth: u32,
}

#[derive(Debug, Clone)]
pub struct TokenDepth {
    pub token: Token,
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
                        if !seen_comp && !meta.has_comparator(iter.clone()) {
                            meta.push(token);
                            meta.push(Token::Comparator(Comparator::Gt));
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
                                meta.push(Token::Logical(Logical::And));
                            } else {
                                eprintln!("Warning: Single & in meta expression {expr}",);
                            }
                        }
                        '|' => {
                            seen_comp = false;
                            if matches!(iter.next(), Some('|')) {
                                meta.push(Token::Logical(Logical::Or));
                            } else {
                                eprintln!("Warning: Single | in meta expression {expr}",);
                            }
                        }
                        '!' => {
                            seen_comp = false;
                            meta.push(Token::Logical(Logical::Not))
                        }
                        '=' => {
                            seen_comp = true;
                            meta.push(match iter.next() {
                                Some('=') => Token::Comparator(Comparator::Eq),
                                Some('>') => Token::Comparator(Comparator::Ge),
                                Some('<') => Token::Comparator(Comparator::Le),
                                _ => {
                                    eprintln!("Warning: Single = in meta expression {expr}",);
                                    Token::Comparator(Comparator::Eq)
                                }
                            });
                        }
                        '>' => {
                            seen_comp = true;
                            meta.push(match iter.peek() {
                                Some('=') => {
                                    iter.next();
                                    Token::Comparator(Comparator::Ge)
                                }
                                _ => Token::Comparator(Comparator::Gt),
                            })
                        }
                        '<' => {
                            seen_comp = true;
                            meta.push(match iter.peek() {
                                Some('=') => {
                                    iter.next();
                                    Token::Comparator(Comparator::Le)
                                }
                                _ => Token::Comparator(Comparator::Lt),
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
                        '+' => meta.push(Token::Operation(Operation::Add)),
                        '*' => meta.push(Token::Operation(Operation::Multiply)),
                        '/' => meta.push(Token::Operation(Operation::Divide)),
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
                meta.push(Token::Comparator(Comparator::Gt));
                meta.push(Token::Number(0));
            }
        }

        meta.finalize();
        meta
    }

    fn push(&mut self, mut token: Token) {
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
            Token::Logical(op) => {
                if self
                    .tokens
                    .iter()
                    .any(|t| matches!(t.token, Token::Comparator(_)) && t.depth < depth)
                {
                    token = Token::Operation(match op {
                        Logical::And => Operation::And,
                        Logical::Or => Operation::Or,
                        Logical::Not => Operation::Not,
                    });
                    if let Some((pos, true)) = depth_range.expr_end {
                        depth_range.expr_end = Some((pos, false));
                    }
                } else if matches!(op, Logical::Or | Logical::And) {
                    let start_prefix = &mut self.tokens[depth_range.start].prefix;
                    if !start_prefix.contains(&Token::Logical(Logical::And))
                        && !start_prefix.contains(&Token::Logical(Logical::Or))
                    {
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
            }
            Token::Comparator(_) => {
                let mut is_static = true;
                let mut start_pos = usize::MAX;
                for (pos, token) in self.tokens.iter_mut().enumerate().rev() {
                    if token.depth >= depth {
                        start_pos = pos;
                        match &token.token {
                            Token::Logical(op) => {
                                if token.depth == depth {
                                    start_pos += 1;
                                    break;
                                } else {
                                    is_static = false;
                                    token.token = Token::Operation(match op {
                                        Logical::And => Operation::And,
                                        Logical::Or => Operation::Or,
                                        Logical::Not => Operation::Not,
                                    });
                                    token.prefix.clear();
                                }
                            }
                            Token::OpenParen
                            | Token::CloseParen
                            | Token::Operation(_)
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
            Token::Tag(_) | Token::Operation(_) => {
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

    fn has_comparator(&self, iter: Peekable<Chars<'_>>) -> bool {
        let mut d = self.depth;
        let mut comp_depth = None;
        let mut logic_depth = None;

        for (pos, ch) in iter.enumerate() {
            match ch {
                '(' => {
                    d += 1;
                }
                ')' => {
                    d = d.saturating_sub(1);
                }
                '>' | '<' | '=' => {
                    comp_depth = Some((pos, d));
                    break;
                }
                '&' | '|' => {
                    if d <= self.depth {
                        logic_depth = Some((pos, d));
                    }
                }
                _ => (),
            }
        }

        println!("comp_depth: {comp_depth:?} {logic_depth:?}");

        match (comp_depth, logic_depth) {
            (Some((comp_pos, comp_depth)), Some((logic_pos, logic_depth))) => {
                match comp_depth.cmp(&logic_depth) {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Equal => comp_pos < logic_pos,
                    _ => false,
                }
            }
            (Some(_), None) => true,
            _ => false,
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
                Token::Logical(Logical::And) | Token::Logical(Logical::Or) => f.write_str(", "),
                Token::Comparator(Comparator::Gt)
                | Token::Comparator(Comparator::Lt)
                | Token::Comparator(Comparator::Eq)
                | Token::Comparator(Comparator::Ge)
                | Token::Comparator(Comparator::Le) => f.write_str(" "),
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
            Token::Logical(Logical::And) => f.write_str("allof("),
            Token::Logical(Logical::Or) => f.write_str("anyof("),
            Token::Logical(Logical::Not) => f.write_str("not "),
            Token::Comparator(comp) => {
                f.write_str("string :value \"")?;
                match comp {
                    Comparator::Eq => f.write_str("eq")?,
                    Comparator::Gt => f.write_str("gt")?,
                    Comparator::Lt => f.write_str("lt")?,
                    Comparator::Ge => f.write_str("ge")?,
                    Comparator::Le => f.write_str("gt")?,
                    _ => unreachable!(),
                }
                f.write_str("\" :comparator \"i;ascii-numeric\" ")
            }

            Token::OpenParen => f.write_str("("),
            Token::CloseParen => f.write_str(")"),
            Token::Operation(Operation::Add) => f.write_str(" + "),
            Token::Operation(Operation::Multiply) => f.write_str(" * "),
            Token::Operation(Operation::Divide) => f.write_str(" / "),
            Token::Operation(Operation::And) => f.write_str(" & "),
            Token::Operation(Operation::Or) => f.write_str(" | "),
            Token::Operation(Operation::Not) => f.write_str("!"),
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
            ("RAZOR2_CHECK + DCC_CHECK + PYZOR_CHECK > 1", ""),
            ("(SUBJECT_IN_BLOCKLIST)", ""),
            ("__HAS_MSGID && !(__SANE_MSGID || __MSGID_COMMENT)", ""),
            ("!__CTYPE_HTML && __X_MAILER_APPLEMAIL && (__MSGID_APPLEMAIL || __MIME_VERSION_APPLEMAIL)", ""),
            ("((__AUTO_GEN_MS||__AUTO_GEN_3||__AUTO_GEN_4) && !__XM_VBULLETIN && !__X_CRON_ENV)", ""),*/
            ("(__WEBMAIL_ACCT + __MAILBOX_FULL + (__TVD_PH_SUBJ_META || __TVD_PH_BODY_META) > 3)", ""),

        ] {
            let meta = MetaExpression::from_meta(expr);
            //println!("{:#?}", meta.tokens);
            let result = meta.to_string();

            println!("{expr}");
            println!("{}", result);

            /*assert_eq!(
                result,
                expected,
                "failed for {expr}"
            );*/
        }
    }
}
