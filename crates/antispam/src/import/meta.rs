use std::fmt::Display;

use super::{
    ast::Parser, tokenizer::Tokenizer, BinaryOperator, Comparator, Expr, Logical, MetaExpression,
    Operation, Token, UnaryOperator, UnwrapResult,
};

// Parse a meta expression into a list of tokens that can be converted into a Sieve test.
impl MetaExpression {
    pub fn from_meta(expr: &str) -> Self {
        let mut tokens = Tokenizer::new(expr).collect::<Vec<_>>();

        // If there are no comparators, we can just turn it into am expression
        if !tokens.iter().any(|t| matches!(t, Token::Comparator(_))) {
            let prev_tokens = tokens;
            tokens = Vec::with_capacity(prev_tokens.len() + 3);
            tokens.push(Token::OpenParen);
            for token in prev_tokens {
                tokens.push(if let Token::Logical(op) = token {
                    match op {
                        Logical::And => Token::Operation(Operation::And),
                        Logical::Or => Token::Operation(Operation::Or),
                        Logical::Not => Token::Logical(Logical::Not),
                    }
                } else {
                    token
                });
            }
            tokens.push(Token::CloseParen);
            tokens.push(Token::Comparator(Comparator::Gt));
            tokens.push(Token::Number(0));
        }

        let expr = Parser::new(&tokens)
            .parse()
            .unwrap_result("parse expression");
        MetaExpression { tokens, expr }
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

impl Expr {
    fn fmt_child(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        parent: Option<&BinaryOperator>,
        in_comp: bool,
    ) -> std::fmt::Result {
        match self {
            Expr::UnaryOp(op, expr) => {
                let add_p =
                    in_comp && !matches!(expr.as_ref(), Expr::Literal(_) | Expr::Identifier(_));
                match op {
                    UnaryOperator::Not => f.write_str(if in_comp { "!" } else { "not " })?,
                    UnaryOperator::Minus => f.write_str("-")?,
                }
                if add_p {
                    f.write_str("(")?;
                }
                expr.fmt_child(f, None, in_comp)?;
                if add_p {
                    f.write_str(")")?;
                }
                Ok(())
            }
            Expr::BinaryOp(left, op, right) => match op {
                BinaryOperator::Or | BinaryOperator::And => {
                    let add_p = parent.map_or(true, |pop| pop.precedence() != op.precedence());
                    if add_p {
                        write!(f, "{op}(")?;
                    }
                    left.fmt_child(f, op.into(), in_comp)?;
                    f.write_str(", ")?;
                    right.fmt_child(f, op.into(), in_comp)?;
                    if add_p {
                        f.write_str(")")
                    } else {
                        Ok(())
                    }
                }
                BinaryOperator::Greater
                | BinaryOperator::Lesser
                | BinaryOperator::GreaterOrEqual
                | BinaryOperator::LesserOrEqual
                | BinaryOperator::Equal => {
                    write!(f, "string :value {op} :comparator \"i;ascii-numeric\" \"")?;
                    let is_literal = matches!(left.as_ref(), Expr::Literal(_));
                    if !is_literal {
                        f.write_str("${")?;
                    }
                    left.fmt_child(f, None, true)?;
                    if !is_literal {
                        f.write_str("}")?;
                    }
                    f.write_str("\" \"")?;
                    let is_literal = matches!(right.as_ref(), Expr::Literal(_));
                    if !is_literal {
                        f.write_str("${")?;
                    }
                    right.fmt_child(f, None, true)?;
                    if !is_literal {
                        f.write_str("}")?;
                    }
                    f.write_str("\"")
                }
                BinaryOperator::Add
                | BinaryOperator::Subtract
                | BinaryOperator::Multiply
                | BinaryOperator::Divide
                | BinaryOperator::BitwiseAnd
                | BinaryOperator::BitwiseOr => {
                    let add_p = parent.map_or(false, |pop| pop.precedence() != op.precedence());
                    if add_p {
                        f.write_str("(")?;
                    }
                    left.fmt_child(f, op.into(), in_comp)?;
                    op.fmt(f)?;
                    right.fmt_child(f, op.into(), in_comp)?;
                    if add_p {
                        f.write_str(")")?;
                    }
                    Ok(())
                }
            },
            Expr::Literal(v) => {
                if !in_comp {
                    write!(
                        f,
                        "string :value \"gt\" :comparator \"i;ascii-numeric\" \"{v}\" \"0\""
                    )
                } else {
                    v.fmt(f)
                }
            }
            Expr::Identifier(i) => {
                if !in_comp {
                    write!(
                        f,
                        "string :value \"gt\" :comparator \"i;ascii-numeric\" \"${{{i}}}\" \"0\"",
                    )
                } else {
                    i.fmt(f)
                }
            }
        }
    }
}

impl Display for MetaExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("if ")?;
        self.expr.fmt_child(f, None, false)
    }
}

impl Display for BinaryOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOperator::Or => f.write_str("anyof"),
            BinaryOperator::And => f.write_str("allof"),
            BinaryOperator::BitwiseOr => f.write_str(" | "),
            BinaryOperator::BitwiseAnd => f.write_str(" & "),
            BinaryOperator::Greater => f.write_str("\"gt\""),
            BinaryOperator::Lesser => f.write_str("\"lt\""),
            BinaryOperator::GreaterOrEqual => f.write_str("\"ge\""),
            BinaryOperator::LesserOrEqual => f.write_str("\"le\""),
            BinaryOperator::Equal => f.write_str("\"eq\""),
            BinaryOperator::Add => f.write_str(" + "),
            BinaryOperator::Subtract => f.write_str(" - "),
            BinaryOperator::Multiply => f.write_str(" * "),
            BinaryOperator::Divide => f.write_str(" / "),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::import::MetaExpression;

    #[test]
    fn parse_meta() {
        for (pos, (expr, expected)) in [
            (
                concat!(
                    "( ! A ) && ",
                    "( B > 20 ) && ",
                    "( C > ( (D * 14 ) / 10) ) && ",
                    "( E < ( 10 * F ) )"
                ),
                "",
            ),
            ("(A || B)", ""),
            ("(A && !B)", ""),
            ("A || B", ""),
            ("(A && (!B && !C && !D))", ""),
            ("(0)", ""),
            ("A + B + C > 1", ""),
            ("(A)", ""),
            ("A && !(B || C)", ""),
            ("!A && B && (C || D)", ""),
            ("((A||B||C) && !D && !E)", ""),
            ("(A + B + (C || D) > 3)", ""),
            (
                "(A || B) > 2 && (C && D) == 0 || ((E+F-G) > 0 || (H||I) <= 4)",
                "",
            ),
            ("(A || B) > (C && D) && E", ""),
            //("", ""),
        ]
        .iter()
        .enumerate()
        {
            let meta = MetaExpression::from_meta(expr);
            //println!("{:#?}", meta.tokens);
            /*if pos != 13 {
                continue;
            }*/

            println!("{expr}");
            //let tokens = Tokenizer::new(expr).collect::<Vec<_>>();
            //println!("{tokens:?}");
            //let mut p = Parser::new(&tokens);
            //let expr = p.parse().unwrap();

            //println!("{:#?}", expr);

            println!("{}\n------------------------------------", meta);

            /*assert_eq!(
                result,
                expected,
                "failed for {expr}"
            );*/
        }
    }
}
