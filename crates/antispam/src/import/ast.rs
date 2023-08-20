use super::{BinaryOperator, Comparator, Expr, Logical, Operation, Token, UnaryOperator};

pub struct Parser<'x> {
    tokens: &'x [Token],
    position: usize,
}

impl<'x> Parser<'x> {
    pub fn new(tokens: &'x [Token]) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    pub fn consume(&mut self) -> Option<&'x Token> {
        if self.position < self.tokens.len() {
            let token = &self.tokens[self.position];
            self.position += 1;
            Some(token)
        } else {
            None
        }
    }

    pub fn peek(&self) -> Option<&'x Token> {
        if self.position < self.tokens.len() {
            Some(&self.tokens[self.position])
        } else {
            None
        }
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(&Token::Number(n)) => {
                self.consume();
                Ok(Expr::Literal(n))
            }
            Some(Token::Tag(ref id)) => {
                self.consume();
                Ok(Expr::Identifier(id.clone()))
            }
            Some(&Token::OpenParen) => {
                self.consume();
                let expr = self.expr();
                if let Some(&Token::CloseParen) = self.peek() {
                    self.consume();
                    expr
                } else {
                    Err("Expected closing parenthesis".to_string())
                }
            }
            _ => Err("Unexpected token in factor".to_string()),
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(&Token::Logical(Logical::Not)) => {
                self.consume();
                let operand = self.primary()?;
                Ok(Expr::UnaryOp(UnaryOperator::Not, Box::new(operand)))
            }
            Some(&Token::Operation(Operation::Subtract)) => {
                self.consume();
                let operand = self.primary()?;
                Ok(Expr::UnaryOp(UnaryOperator::Minus, Box::new(operand)))
            }
            _ => self.primary(),
        }
    }

    fn factor(&mut self) -> Result<Expr, String> {
        let mut left = self.unary()?;

        while let Some(op @ Token::Operation(Operation::Multiply | Operation::Divide)) = self.peek()
        {
            self.consume();
            let right = self.unary()?;
            left = Expr::BinaryOp(Box::new(left), op.into(), Box::new(right));
        }

        Ok(left)
    }

    fn term(&mut self) -> Result<Expr, String> {
        let mut left = self.factor()?;

        while let Some(op @ Token::Operation(Operation::Add | Operation::Subtract)) = self.peek() {
            self.consume();
            let right = self.factor()?;
            left = Expr::BinaryOp(Box::new(left), op.into(), Box::new(right));
        }

        Ok(left)
    }

    fn bitwise(&mut self) -> Result<Expr, String> {
        let mut left = self.term()?;
        while let Some(op @ Token::Operation(Operation::And | Operation::Or)) = self.peek() {
            self.consume();
            let right = self.term()?;
            left = Expr::BinaryOp(Box::new(left), op.into(), Box::new(right));
        }
        Ok(left)
    }

    fn comparison(&mut self) -> Result<Expr, String> {
        let mut left = self.bitwise()?;

        while let Some(op @ Token::Comparator(_)) = self.peek() {
            self.consume();
            let right = self.bitwise()?;
            left = Expr::BinaryOp(Box::new(left), op.into(), Box::new(right));
        }

        Ok(left)
    }

    fn logical_and(&mut self) -> Result<Expr, String> {
        let mut left = self.comparison()?;

        while let Some(Token::Logical(Logical::And)) = self.peek() {
            self.consume();
            let right = self.comparison()?;
            left = Expr::BinaryOp(Box::new(left), BinaryOperator::And, Box::new(right));
        }
        Ok(left)
    }

    fn logical_or(&mut self) -> Result<Expr, String> {
        let mut left = self.logical_and()?;

        while let Some(Token::Logical(Logical::Or)) = self.peek() {
            self.consume();
            let right = self.logical_and()?;
            left = Expr::BinaryOp(Box::new(left), BinaryOperator::Or, Box::new(right));
        }
        Ok(left)
    }

    fn expr(&mut self) -> Result<Expr, String> {
        self.logical_or()
    }

    pub fn parse(&mut self) -> Result<Expr, String> {
        let result = self.expr()?;
        if self.position < self.tokens.len() {
            println!("{result:#?}\n {} {}", self.position, self.tokens.len());
            Err("Unexpected tokens at the end of the expression".to_string())
        } else {
            Ok(result)
        }
    }
}

impl From<&Token> for BinaryOperator {
    fn from(value: &Token) -> Self {
        match value {
            Token::Operation(Operation::Add) => Self::Add,
            Token::Operation(Operation::Multiply) => Self::Multiply,
            Token::Operation(Operation::Divide) => Self::Divide,
            Token::Operation(Operation::Subtract) => Self::Subtract,
            Token::Operation(Operation::And) => Self::BitwiseAnd,
            Token::Operation(Operation::Or) => Self::BitwiseOr,
            Token::Logical(Logical::And) => Self::And,
            Token::Logical(Logical::Or) => Self::Or,
            Token::Comparator(Comparator::Gt) => Self::Greater,
            Token::Comparator(Comparator::Lt) => Self::Lesser,
            Token::Comparator(Comparator::Ge) => Self::GreaterOrEqual,
            Token::Comparator(Comparator::Le) => Self::LesserOrEqual,
            Token::Comparator(Comparator::Eq) => Self::Equal,
            _ => panic!("Invalid token"),
        }
    }
}
