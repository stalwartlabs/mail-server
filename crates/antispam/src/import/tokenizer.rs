use super::{Comparator, Logical, Operation, Token};

pub struct Tokenizer<'x> {
    expr: &'x str,
    iter: std::iter::Peekable<std::str::Chars<'x>>,
    buf: String,
    depth: u32,
    comparator_depth: u32,
    next_token: Option<Token>,
}

impl<'x> Tokenizer<'x> {
    pub fn new(expr: &'x str) -> Self {
        Self {
            expr,
            iter: expr.chars().peekable(),
            buf: String::new(),
            depth: 0,
            next_token: None,
            comparator_depth: u32::MAX,
        }
    }
}

impl<'x> Iterator for Tokenizer<'x> {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(token) = self.next_token.take() {
            return Some(token);
        }

        while let Some(ch) = self.iter.next() {
            match ch {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '_' => {
                    self.buf.push(ch);
                }
                _ => {
                    let mut depth = self.depth;
                    let prev_token = if !self.buf.is_empty() {
                        Token::from(std::mem::take(&mut self.buf)).into()
                    } else {
                        None
                    };
                    let token = match ch {
                        '&' | '|' => {
                            if matches!(self.iter.next(), Some(c) if c == ch) {
                                Token::Logical(if ch == '&' { Logical::And } else { Logical::Or })
                            } else {
                                eprintln!("Warning: Single {ch} in meta expression {}", self.expr);
                                return None;
                            }
                        }
                        '!' => Token::Logical(Logical::Not),
                        '=' => match self.iter.next() {
                            Some('=') => Token::Comparator(Comparator::Eq),
                            Some('>') => Token::Comparator(Comparator::Ge),
                            Some('<') => Token::Comparator(Comparator::Le),
                            _ => {
                                eprintln!("Warning: Single = in meta expression {}", self.expr);
                                Token::Comparator(Comparator::Eq)
                            }
                        },
                        '>' => match self.iter.peek() {
                            Some('=') => {
                                self.iter.next();
                                Token::Comparator(Comparator::Ge)
                            }
                            _ => Token::Comparator(Comparator::Gt),
                        },
                        '<' => match self.iter.peek() {
                            Some('=') => {
                                self.iter.next();
                                Token::Comparator(Comparator::Le)
                            }
                            _ => Token::Comparator(Comparator::Lt),
                        },
                        '(' => {
                            self.depth += 1;
                            Token::OpenParen
                        }
                        ')' => {
                            if self.depth == 0 {
                                eprintln!(
                                    "Warning: Unmatched close parenthesis in meta expression {}",
                                    self.expr
                                );
                                return None;
                            }
                            self.depth -= 1;
                            depth = self.depth;

                            Token::CloseParen
                        }
                        '+' => Token::Operation(Operation::Add),
                        '*' => Token::Operation(Operation::Multiply),
                        '/' => Token::Operation(Operation::Divide),
                        '-' => Token::Operation(Operation::Subtract),
                        ' ' => {
                            if let Some(prev_token) = prev_token {
                                return Some(prev_token);
                            } else {
                                continue;
                            }
                        }
                        _ => {
                            eprintln!(
                                "Warning: Invalid character {ch} in meta expression {}",
                                self.expr
                            );
                            return None;
                        }
                    };

                    if matches!(token, Token::Comparator(_)) {
                        self.comparator_depth = depth;
                    }

                    return Some(if let Some(prev_token) = prev_token {
                        self.next_token = Some(token);
                        prev_token
                    } else {
                        token
                    });
                }
            }
        }

        if self.depth > 0 {
            eprintln!(
                "Warning: Unmatched open parenthesis in meta expression {}",
                self.expr
            );
            None
        } else if !self.buf.is_empty() {
            Some(Token::from(std::mem::take(&mut self.buf)))
        } else {
            None
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
