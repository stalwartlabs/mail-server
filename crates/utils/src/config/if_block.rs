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

use crate::expr::{Constant, Expression, Token, Variable};

use super::{utils::AsKey, Config};

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

    pub async fn eval<'x, V, F, R>(&'x self, var: V, mut fnc: F) -> Variable<'x>
    where
        V: Fn(u32) -> Variable<'x>,
        F: FnMut(u32, Vec<Variable<'x>>) -> R,
        R: std::future::Future<Output = Variable<'x>> + Send,
    {
        let mut captures = Vec::new();

        for if_then in &self.if_then {
            if if_then
                .expr
                .eval(&var, &mut fnc, &mut captures)
                .await
                .to_bool()
            {
                return if_then.then.eval(&var, &mut fnc, &mut captures).await;
            }
        }

        self.default.eval(&var, &mut fnc, &mut captures).await
    }

    pub fn is_empty(&self) -> bool {
        self.default.is_empty() && self.if_then.is_empty()
    }
}

impl Config {
    pub fn parse_if_block(
        &self,
        prefix: impl AsKey,
        token_map: impl Fn(&str) -> Result<Token, String>,
    ) -> super::Result<Option<IfBlock>> {
        let key = prefix.as_key();
        let prefix = prefix.as_prefix();

        let mut found_if = false;
        let mut found_else = "";
        let mut found_then = false;

        // Parse conditions
        let mut if_block = IfBlock {
            key,
            ..Default::default()
        };
        let mut last_array_pos = "";
        let key = &if_block.key;

        for (item, value) in &self.keys {
            if let Some(suffix_) = item.strip_prefix(&prefix) {
                if let Some((array_pos, suffix)) = suffix_.split_once('.') {
                    let if_key = suffix.split_once('.').map(|(v, _)| v).unwrap_or(suffix);
                    if if_key == "if" {
                        if array_pos != last_array_pos {
                            if !last_array_pos.is_empty() && !found_then {
                                return Err(format!(
                                    "Missing 'then' in 'if' condition {} for property {:?}.",
                                    last_array_pos.parse().unwrap_or(0) + 1,
                                    key
                                ));
                            }

                            if_block.if_then.push(IfThen {
                                expr: Expression::parse(key.as_str(), value, &token_map)?,
                                then: Expression::default(),
                            });

                            found_then = false;
                            last_array_pos = array_pos;
                        }

                        found_if = true;
                    } else if if_key == "else" {
                        if found_else.is_empty() {
                            if found_if {
                                if_block.default =
                                    Expression::parse(key.as_str(), value, &token_map)?;
                                found_else = array_pos;
                            } else {
                                return Err(format!(
                                    "Found 'else' before 'if' for property {key:?}.",
                                ));
                            }
                        } else if array_pos != found_else {
                            return Err(format!("Multiple 'else' found for property {key:?}."));
                        }
                    } else if if_key == "then" {
                        if found_else.is_empty() {
                            if array_pos == last_array_pos {
                                if !found_then {
                                    if_block.if_then.last_mut().unwrap().then =
                                        Expression::parse(key.as_str(), value, &token_map)?;
                                    found_then = true;
                                }
                            } else {
                                return Err(format!(
                                    "Found 'then' without 'if' for property {key:?}.",
                                ));
                            }
                        } else {
                            return Err(format!(
                                "Found 'then' in 'else' block for property {key:?}.",
                            ));
                        }
                    }
                } else {
                    return Err(format!("Invalid property {item:?} found in 'if' block."));
                }
            } else if item == key {
                // There is a single value, parse and return
                if_block.default = Expression::parse(key.as_str(), value, &token_map)?;
                return Ok(Some(if_block));
            }
        }

        if !found_if {
            Ok(None)
        } else if !found_then {
            Err(format!(
                "Missing 'then' in 'if' condition {} for property {:?}.",
                last_array_pos.parse().unwrap_or(0) + 1,
                key
            ))
        } else if found_else.is_empty() {
            Err(format!("Missing 'else' for property {key:?}."))
        } else {
            Ok(Some(if_block))
        }
    }
}
