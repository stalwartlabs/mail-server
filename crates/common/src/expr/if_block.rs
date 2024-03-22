/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use utils::config::{utils::AsKey, Config};

use crate::expr::{Constant, Expression};

use super::{
    parser::ExpressionParser,
    tokenizer::{TokenMap, Tokenizer},
    ExpressionItem,
};

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct IfThen {
    pub expr: Expression,
    pub then: Expression,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct IfBlock {
    pub key: String,
    pub if_then: Vec<IfThen>,
    pub default: Expression,
}

impl IfBlock {
    pub fn new<T: Into<Constant>>(value: T) -> Self {
        Self {
            key: String::new(),
            if_then: Vec::new(),
            default: Expression::from(value),
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
            ..Default::default()
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
            config.new_missing_property(if_block.key);
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
