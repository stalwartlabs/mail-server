/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::{utils::AsKey, Config};

use crate::expr::{Constant, Expression};

use super::{
    parser::ExpressionParser,
    tokenizer::{TokenMap, Tokenizer},
    ConstantValue, ExpressionItem,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct IfThen {
    pub expr: Expression,
    pub then: Expression,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct IfBlock {
    pub key: String,
    pub if_then: Vec<IfThen>,
    pub default: Expression,
}

impl IfBlock {
    pub fn new<T: ConstantValue>(
        key: impl Into<String>,
        if_thens: impl IntoIterator<Item = (&'static str, &'static str)>,
        default: impl AsRef<str>,
    ) -> Self {
        let token_map = TokenMap::default()
            .with_all_variables()
            .with_constants::<T>();

        Self {
            key: key.into(),
            if_then: if_thens
                .into_iter()
                .map(|(if_, then)| IfThen {
                    expr: Expression::parse(&token_map, if_),
                    then: Expression::parse(&token_map, then),
                })
                .collect(),
            default: Expression::parse(&token_map, default.as_ref()),
        }
    }

    pub fn empty(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            if_then: Default::default(),
            default: Expression {
                items: Default::default(),
            },
        }
    }

    pub fn is_empty(&self) -> bool {
        self.default.is_empty() && self.if_then.is_empty()
    }
}

impl Expression {
    pub fn try_parse(
        config: &mut Config,
        key: impl AsKey,
        token_map: &TokenMap,
    ) -> Option<Expression> {
        if let Some(expr) = config.value(key.as_key()) {
            match ExpressionParser::new(Tokenizer::new(expr, token_map)).parse() {
                Ok(expr) => Some(expr),
                Err(err) => {
                    config.new_parse_error(key, err);
                    None
                }
            }
        } else {
            None
        }
    }

    fn parse(token_map: &TokenMap, expr: &str) -> Self {
        ExpressionParser::new(Tokenizer::new(expr, token_map))
            .parse()
            .unwrap()
    }
}

impl IfBlock {
    pub fn try_parse(
        config: &mut Config,
        prefix: impl AsKey,
        token_map: &TokenMap,
    ) -> Option<IfBlock> {
        let key = prefix.as_key();

        // Parse conditions
        let mut if_block = IfBlock {
            key,
            if_then: Default::default(),
            default: Expression {
                items: Default::default(),
            },
        };

        // Try first with a single value
        if config.contains_key(if_block.key.as_str()) {
            if_block.default = Expression::try_parse(config, &if_block.key, token_map)?;
            return Some(if_block);
        }

        // Collect prefixes
        let prefix = prefix.as_prefix();
        let keys = config
            .keys
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect::<Vec<_>>();
        let mut found_if = false;
        let mut found_else = "";
        let mut found_then = false;
        let mut last_array_pos = "";

        for item in &keys {
            let suffix_ = item.strip_prefix(&prefix).unwrap();

            if let Some((array_pos, suffix)) = suffix_.split_once('.') {
                let if_key = suffix.split_once('.').map(|(v, _)| v).unwrap_or(suffix);
                if if_key == "if" {
                    if array_pos != last_array_pos {
                        if !last_array_pos.is_empty() && !found_then {
                            config.new_parse_error(
                                if_block.key,
                                format!(
                                    "Missing 'then' in 'if' condition {}.",
                                    last_array_pos.parse().unwrap_or(0) + 1,
                                ),
                            );
                            return None;
                        }

                        if_block.if_then.push(IfThen {
                            expr: Expression::try_parse(config, item, token_map)?,
                            then: Expression::default(),
                        });

                        found_then = false;
                        last_array_pos = array_pos;
                    }

                    found_if = true;
                } else if if_key == "else" {
                    if found_else.is_empty() {
                        if found_if {
                            if_block.default = Expression::try_parse(config, item, token_map)?;
                            found_else = array_pos;
                        } else {
                            config.new_parse_error(if_block.key, "Found 'else' before 'if'");
                            return None;
                        }
                    } else if array_pos != found_else {
                        config.new_parse_error(if_block.key, "Multiple 'else' found");
                        return None;
                    }
                } else if if_key == "then" {
                    if found_else.is_empty() {
                        if array_pos == last_array_pos {
                            if !found_then {
                                if_block.if_then.last_mut().unwrap().then =
                                    Expression::try_parse(config, item, token_map)?;
                                found_then = true;
                            }
                        } else {
                            config.new_parse_error(if_block.key, "Found 'then' without 'if'");
                            return None;
                        }
                    } else {
                        config.new_parse_error(if_block.key, "Found 'then' in 'else' block");
                        return None;
                    }
                }
            } else {
                config.new_parse_error(
                    if_block.key,
                    format!("Invalid property {item:?} found in 'if' block."),
                );
                return None;
            }
        }

        if !found_if {
            None
        } else if !found_then {
            config.new_parse_error(
                if_block.key,
                format!(
                    "Missing 'then' in 'if' condition {}",
                    last_array_pos.parse().unwrap_or(0) + 1,
                ),
            );
            None
        } else if found_else.is_empty() {
            config.new_parse_error(if_block.key, "Missing 'else'");
            None
        } else {
            Some(if_block)
        }
    }

    pub fn into_default(self, key: impl Into<String>) -> IfBlock {
        IfBlock {
            key: key.into(),
            if_then: Default::default(),
            default: self.default,
        }
    }

    pub fn default_string(&self) -> Option<&str> {
        for expr_item in &self.default.items {
            if let ExpressionItem::Constant(Constant::String(value)) = expr_item {
                return Some(value.as_str());
            }
        }

        None
    }

    pub fn into_default_string(self) -> Option<String> {
        for expr_item in self.default.items {
            if let ExpressionItem::Constant(Constant::String(value)) = expr_item {
                return Some(value);
            }
        }

        None
    }
}
