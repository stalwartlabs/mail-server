/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{tokenizer::Tokenizer, BinaryOperator, Expression, ExpressionItem, Token};

pub struct ExpressionParser<'x> {
    pub(crate) tokenizer: Tokenizer<'x>,
    pub(crate) output: Vec<ExpressionItem>,
    operator_stack: Vec<(Token, Option<usize>)>,
    arg_count: Vec<i32>,
}

pub(crate) const ID_ARRAY_ACCESS: u32 = u32::MAX;
pub(crate) const ID_ARRAY_BUILD: u32 = u32::MAX - 1;

impl<'x> ExpressionParser<'x> {
    pub fn new(tokenizer: Tokenizer<'x>) -> Self {
        Self {
            tokenizer,
            output: Vec::new(),
            operator_stack: Vec::new(),
            arg_count: Vec::new(),
        }
    }

    pub fn parse(mut self) -> Result<Expression, String> {
        let mut last_is_var_or_fnc = false;

        while let Some(token) = self.tokenizer.next()? {
            let mut is_var_or_fnc = false;
            match token {
                Token::Variable(v) => {
                    self.inc_arg_count();
                    is_var_or_fnc = true;
                    self.output.push(ExpressionItem::Variable(v))
                }
                Token::Constant(c) => {
                    self.inc_arg_count();
                    self.output.push(ExpressionItem::Constant(c))
                }
                Token::Capture(c) => {
                    self.inc_arg_count();
                    self.output.push(ExpressionItem::Capture(c))
                }
                Token::UnaryOperator(uop) => {
                    self.operator_stack.push((Token::UnaryOperator(uop), None))
                }
                Token::OpenParen => self.operator_stack.push((token, None)),
                Token::CloseParen | Token::CloseBracket => {
                    let expect_token = if matches!(token, Token::CloseParen) {
                        Token::OpenParen
                    } else {
                        Token::OpenBracket
                    };
                    loop {
                        match self.operator_stack.pop() {
                            Some((t, _)) if t == expect_token => {
                                break;
                            }
                            Some((Token::BinaryOperator(bop), jmp_pos)) => {
                                self.update_jmp_pos(jmp_pos);
                                self.output.push(ExpressionItem::BinaryOperator(bop))
                            }
                            Some((Token::UnaryOperator(uop), _)) => {
                                self.output.push(ExpressionItem::UnaryOperator(uop))
                            }
                            _ => return Err("Mismatched parentheses".to_string()),
                        }
                    }

                    match self.operator_stack.last() {
                        Some((Token::Function { id, num_args, name }, _)) => {
                            let got_args = self.arg_count.pop().unwrap();
                            if got_args != *num_args as i32 {
                                return Err(if *id != u32::MAX {
                                    format!(
                                        "Expression function {:?} expected {} arguments, got {}",
                                        name, num_args, got_args
                                    )
                                } else {
                                    "Missing array index".to_string()
                                });
                            }

                            let expr = match *id {
                                ID_ARRAY_ACCESS => ExpressionItem::ArrayAccess,
                                ID_ARRAY_BUILD => ExpressionItem::ArrayBuild(*num_args),
                                id => ExpressionItem::Function {
                                    id,
                                    num_args: *num_args,
                                },
                            };

                            self.operator_stack.pop();
                            self.output.push(expr);
                        }
                        Some((Token::Regex(regex), _)) => {
                            if self.arg_count.pop().unwrap() != 1 {
                                return Err("Expression function \"matches\" expected 2 arguments"
                                    .to_string());
                            }
                            self.output.push(ExpressionItem::Regex(regex.clone()));
                            self.operator_stack.pop();
                        }
                        _ => {}
                    }

                    is_var_or_fnc = true;
                }
                Token::BinaryOperator(bop) => {
                    self.dec_arg_count();
                    while let Some((top_token, prev_jmp_pos)) = self.operator_stack.last() {
                        match top_token {
                            Token::BinaryOperator(top_bop) => {
                                if bop.precedence() <= top_bop.precedence() {
                                    let top_bop = *top_bop;
                                    let jmp_pos = *prev_jmp_pos;
                                    self.update_jmp_pos(jmp_pos);
                                    self.operator_stack.pop();
                                    self.output.push(ExpressionItem::BinaryOperator(top_bop));
                                } else {
                                    break;
                                }
                            }
                            Token::UnaryOperator(top_uop) => {
                                let top_uop = *top_uop;
                                self.operator_stack.pop();
                                self.output.push(ExpressionItem::UnaryOperator(top_uop));
                            }
                            _ => break,
                        }
                    }

                    // Add jump instruction for short-circuiting
                    let jmp_pos = match bop {
                        BinaryOperator::And => {
                            self.output
                                .push(ExpressionItem::JmpIf { val: false, pos: 0 });
                            Some(self.output.len() - 1)
                        }
                        BinaryOperator::Or => {
                            self.output
                                .push(ExpressionItem::JmpIf { val: true, pos: 0 });
                            Some(self.output.len() - 1)
                        }
                        _ => None,
                    };

                    self.operator_stack
                        .push((Token::BinaryOperator(bop), jmp_pos));
                }
                Token::Function { id, name, num_args } => {
                    self.inc_arg_count();
                    self.arg_count.push(0);
                    self.operator_stack
                        .push((Token::Function { id, name, num_args }, None))
                }
                Token::Regex(regex) => {
                    self.inc_arg_count();
                    self.arg_count.push(0);
                    self.operator_stack.push((Token::Regex(regex), None))
                }
                Token::OpenBracket => {
                    // Array functions
                    let (id, num_args, arg_count) = if last_is_var_or_fnc {
                        (ID_ARRAY_ACCESS, 2, 1)
                    } else {
                        self.inc_arg_count();
                        (ID_ARRAY_BUILD, 0, 0)
                    };
                    self.arg_count.push(arg_count);
                    self.operator_stack.push((
                        Token::Function {
                            id,
                            name: "array".into(),
                            num_args,
                        },
                        None,
                    ));
                    self.operator_stack.push((token, None));
                }
                Token::Comma => {
                    while let Some((token, jmp_pos)) = self.operator_stack.last() {
                        match token {
                            Token::OpenParen => break,
                            Token::BinaryOperator(bop) => {
                                let bop = *bop;
                                let jmp_pos = *jmp_pos;
                                self.update_jmp_pos(jmp_pos);
                                self.output.push(ExpressionItem::BinaryOperator(bop));
                                self.operator_stack.pop();
                            }
                            Token::UnaryOperator(uop) => {
                                self.output.push(ExpressionItem::UnaryOperator(*uop));
                                self.operator_stack.pop();
                            }
                            _ => break,
                        }
                    }
                }
            }
            last_is_var_or_fnc = is_var_or_fnc;
        }

        while let Some((token, jmp_pos)) = self.operator_stack.pop() {
            match token {
                Token::BinaryOperator(bop) => {
                    self.update_jmp_pos(jmp_pos);
                    self.output.push(ExpressionItem::BinaryOperator(bop))
                }
                Token::UnaryOperator(uop) => self.output.push(ExpressionItem::UnaryOperator(uop)),
                _ => return Err("Invalid token on the operator stack".to_string()),
            }
        }

        if self.operator_stack.is_empty() {
            Ok(Expression { items: self.output })
        } else {
            Err("Invalid expression".to_string())
        }
    }

    fn inc_arg_count(&mut self) {
        if let Some(x) = self.arg_count.last_mut() {
            *x = x.saturating_add(1);
            let op_pos = self.operator_stack.len().saturating_sub(2);
            match self.operator_stack.get_mut(op_pos) {
                Some((Token::Function { num_args, id, .. }, _)) if *id == ID_ARRAY_BUILD => {
                    *num_args += 1;
                }
                _ => {}
            }
        }
    }

    fn dec_arg_count(&mut self) {
        if let Some(x) = self.arg_count.last_mut() {
            *x = x.saturating_sub(1);
        }
    }

    fn update_jmp_pos(&mut self, jmp_pos: Option<usize>) {
        if let Some(jmp_pos) = jmp_pos {
            let cur_pos = self.output.len();
            if let ExpressionItem::JmpIf { pos, .. } = &mut self.output[jmp_pos] {
                *pos = (cur_pos - jmp_pos) as u32;
            } else {
                #[cfg(test)]
                panic!("Invalid jump position");
            }
        }
    }
}

impl BinaryOperator {
    fn precedence(&self) -> i32 {
        match self {
            BinaryOperator::Multiply | BinaryOperator::Divide => 7,
            BinaryOperator::Add | BinaryOperator::Subtract => 6,
            BinaryOperator::Gt | BinaryOperator::Ge | BinaryOperator::Lt | BinaryOperator::Le => 5,
            BinaryOperator::Eq | BinaryOperator::Ne => 4,
            BinaryOperator::Xor => 3,
            BinaryOperator::And => 2,
            BinaryOperator::Or => 1,
        }
    }
}
