use std::collections::{HashMap, HashSet};

use super::Token;

#[derive(Debug, Clone)]
pub struct MetaExpression {
    pub tokens: Vec<Token>,
    pub token_depth: Vec<u32>,
}

impl MetaExpression {
    pub fn from_meta(meta: &str) -> Self {
        let mut tokens = Vec::new();
        let mut token_depth = Vec::new();
        let mut seen_comp = false;
        let mut buf = String::new();
        let mut pc = 0;
        let mut iter = meta.chars().peekable();

        while let Some(ch) = iter.next() {
            match ch {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '_' => {
                    buf.push(ch);
                }
                _ => {
                    if !buf.is_empty() {
                        let token = Token::from(buf);
                        buf = String::new();
                        if matches!(token, Token::Tag(_))
                            && !seen_comp
                            && matches!(
                                iter.clone()
                                    .find(|t| { ['&', '|', '>', '<', '='].contains(t) }),
                                None | Some('&' | '|')
                            )
                        {
                            tokens.push(token);
                            tokens.push(Token::Gt);
                            tokens.push(Token::Number(0));
                            token_depth.extend_from_slice(&[pc, pc, pc]);
                            seen_comp = true;
                        } else {
                            token_depth.push(pc);
                            tokens.push(token);
                        }
                    }

                    match ch {
                        '&' => {
                            seen_comp = false;
                            if matches!(iter.next(), Some('&')) {
                                tokens.push(Token::And);
                                token_depth.push(pc);
                            } else {
                                eprintln!("Warning: Single & in meta expression {meta} at {pc}",);
                            }
                        }
                        '|' => {
                            seen_comp = false;
                            if matches!(iter.next(), Some('|')) {
                                tokens.push(Token::Or);
                                token_depth.push(pc);
                            } else {
                                eprintln!("Warning: Single | in meta expression {meta} at {pc}",);
                            }
                        }
                        '!' => {
                            seen_comp = false;
                            token_depth.push(pc);
                            tokens.push(Token::Not)
                        }
                        '=' => {
                            seen_comp = true;
                            token_depth.push(pc);
                            tokens.push(match iter.next() {
                                Some('=') => Token::Eq,
                                Some('>') => Token::Ge,
                                Some('<') => Token::Le,
                                _ => {
                                    eprintln!(
                                        "Warning: Single = in meta expression {meta} at {pc}",
                                    );
                                    Token::Eq
                                }
                            });
                        }
                        '>' => {
                            seen_comp = true;
                            token_depth.push(pc);
                            tokens.push(match iter.peek() {
                                Some('=') => {
                                    iter.next();
                                    Token::Ge
                                }
                                _ => Token::Gt,
                            })
                        }
                        '<' => {
                            seen_comp = true;
                            token_depth.push(pc);
                            tokens.push(match iter.peek() {
                                Some('=') => {
                                    iter.next();
                                    Token::Le
                                }
                                _ => Token::Lt,
                            })
                        }
                        '(' => {
                            token_depth.push(pc);
                            pc += 1;
                            tokens.push(Token::OpenParen)
                        }
                        ')' => {
                            if pc > 0 {
                                pc -= 1;
                            } else {
                                eprintln!(
                                    "Warning: Unmatched close parenthesis in meta expression {meta}"
                                );
                            }
                            token_depth.push(pc);
                            tokens.push(Token::CloseParen)
                        }
                        '+' => {
                            token_depth.push(pc);
                            tokens.push(Token::Add)
                        }
                        '*' => {
                            token_depth.push(pc);
                            tokens.push(Token::Multiply)
                        }
                        '/' => {
                            token_depth.push(pc);
                            tokens.push(Token::Divide)
                        }
                        ' ' => {}
                        _ => {
                            eprintln!("Warning: Invalid character {ch} in meta expression {meta}");
                            break;
                        }
                    }
                }
            }
        }

        if pc > 0 {
            eprintln!("Warning: Unmatched open parenthesis in meta expression {meta}");
        }

        if !buf.is_empty() {
            token_depth.push(pc);
            tokens.push(Token::from(buf));
            if !seen_comp {
                tokens.push(Token::Gt);
                tokens.push(Token::Number(0));
                token_depth.push(pc);
                token_depth.push(pc);
            }
        }

        MetaExpression {
            tokens,
            token_depth,
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

impl From<MetaExpression> for String {
    fn from(meta: MetaExpression) -> Self {
        let mut script = String::from("if ");
        let mut tokens = meta.tokens.iter().zip(meta.token_depth.iter()).enumerate();
        let mut expr_end = None;

        // Find start and end of logical expressions
        let mut logical_pos_start: HashMap<usize, Token> = HashMap::new();
        let mut logical_pos_end: HashSet<usize> = HashSet::new();
        let mut depth_starts: HashMap<u32, usize> = HashMap::new();
        for (pos, (token, depth)) in tokens.clone() {
            if !depth_starts.contains_key(depth) {
                depth_starts.insert(*depth, pos);
            }
            if matches!(token, Token::And | Token::Or) {
                let block_start = *depth_starts.get(depth).unwrap();

                if let std::collections::hash_map::Entry::Vacant(e) =
                    logical_pos_start.entry(block_start)
                {
                    e.insert(token.clone());
                    // Find end
                    let mut logical_end = usize::MAX;
                    for (p, (_, d)) in tokens.clone() {
                        if depth == d {
                            logical_end = p;
                        }
                    }
                    logical_pos_end.insert(logical_end);
                }
            }
        }

        while let Some((pos, (token, depth))) = tokens.next() {
            // Add blocks
            if let Some(token) = logical_pos_start.remove(&pos) {
                match token {
                    Token::And => script.push_str("allof("),
                    Token::Or => script.push_str("anyof("),
                    _ => unreachable!(),
                }
            } else {
                match token {
                    Token::And | Token::Or => script.push_str(", "),
                    Token::Not => script.push_str("not "),
                    _ => (),
                }
            }

            // Find expression type
            if expr_end.is_none() {
                if let Some((
                    pos,
                    (token @ (Token::Eq | Token::Gt | Token::Lt | Token::Ge | Token::Le), _),
                )) = tokens.clone().find(|(_, (t, d))| {
                    depth == *d
                        && matches!(
                            t,
                            Token::Eq
                                | Token::Gt
                                | Token::Lt
                                | Token::Ge
                                | Token::Le
                                | Token::Not
                                | Token::And
                                | Token::Or
                        )
                }) {
                    script.push_str("string :");
                    match token {
                        Token::Eq => script.push_str("eq"),
                        Token::Gt => script.push_str("gt"),
                        Token::Lt => script.push_str("lt"),
                        Token::Ge => script.push_str("ge"),
                        Token::Le => script.push_str("gt"),
                        _ => unreachable!(),
                    }
                    script.push_str(" \"");

                    // Find expression end
                    for (p, (token, d)) in tokens.clone() {
                        if p > pos {
                            if depth <= d {
                                if matches!(token, Token::And | Token::Or) {
                                    expr_end = Some(p - 1);
                                    break;
                                } else {
                                    expr_end = Some(p);
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
            }

            match token {
                Token::Tag(tag) => {
                    script.push_str(tag);
                }
                Token::Number(number) => {
                    script.push_str(&number.to_string());
                }
                Token::And | Token::Or | Token::Not => {}
                Token::Gt | Token::Lt | Token::Eq | Token::Ge | Token::Le => {
                    script.push_str("\" \"");
                }
                Token::OpenParen => {
                    script.push('(');
                }
                Token::CloseParen => {
                    script.push(')');
                }
                Token::Add => {
                    script.push_str(" + ");
                }
                Token::Multiply => {
                    script.push_str(" * ");
                }
                Token::Divide => {
                    script.push_str(" / ");
                }
            }

            // Add end of expression
            if expr_end == Some(pos) {
                script.push_str("\"");
                expr_end = None;
            }

            // Add end of logical block
            if logical_pos_end.contains(&pos) {
                script.push(')');
            }
        }

        script
    }
}

#[cfg(test)]
mod test {
    use super::MetaExpression;

    #[test]
    fn parse_meta() {
        for (expr, expected) in [
            (
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
            /*(("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),
            ("", ""),*/
        ] {
            let meta = MetaExpression::from_meta(expr);
            //println!("{:?}", meta.tokens);
            let result = String::from(meta);

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
