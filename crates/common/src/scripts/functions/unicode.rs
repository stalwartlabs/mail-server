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

use sieve::{runtime::Variable, Context};
use unicode_security::MixedScript;

pub fn fn_is_ascii<'x>(_: &'x Context<'x, ()>, v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.chars().all(|c| c.is_ascii()),
        Variable::Integer(_) | Variable::Float(_) => true,
        Variable::Array(a) => a.iter().all(|v| match v {
            Variable::String(s) => s.chars().all(|c| c.is_ascii()),
            _ => true,
        }),
    }
    .into()
}

pub fn fn_has_zwsp<'x>(_: &'x Context<'x, ()>, v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.chars().any(|c| c.is_zwsp()),
        Variable::Array(a) => a.iter().any(|v| match v {
            Variable::String(s) => s.chars().any(|c| c.is_zwsp()),
            _ => true,
        }),
        Variable::Integer(_) | Variable::Float(_) => false,
    }
    .into()
}

pub fn fn_has_obscured<'x>(_: &'x Context<'x, ()>, v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.chars().any(|c| c.is_obscured()),
        Variable::Array(a) => a.iter().any(|v| match v {
            Variable::String(s) => s.chars().any(|c| c.is_obscured()),
            _ => true,
        }),
        Variable::Integer(_) | Variable::Float(_) => false,
    }
    .into()
}

trait CharUtils {
    fn is_zwsp(&self) -> bool;
    fn is_obscured(&self) -> bool;
}

impl CharUtils for char {
    fn is_zwsp(&self) -> bool {
        matches!(
            self,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}'
        )
    }

    fn is_obscured(&self) -> bool {
        matches!(
            self,
            '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202F}'
                | '\u{205F}'..='\u{206F}'
                | '\u{FEFF}'
        )
    }
}

pub fn fn_cure_text<'x>(_: &'x Context<'x, ()>, v: Vec<Variable>) -> Variable {
    decancer::cure(v[0].to_string().as_ref(), decancer::Options::default())
        .map(|s| s.into_str())
        .unwrap_or_default()
        .into()
}

pub fn fn_unicode_skeleton<'x>(_: &'x Context<'x, ()>, v: Vec<Variable>) -> Variable {
    unicode_security::skeleton(v[0].to_string().as_ref())
        .collect::<String>()
        .into()
}

pub fn fn_is_single_script<'x>(_: &'x Context<'x, ()>, v: Vec<Variable>) -> Variable {
    let text = v[0].to_string();
    if !text.is_empty() {
        text.as_ref().is_single_script()
    } else {
        true
    }
    .into()
}
