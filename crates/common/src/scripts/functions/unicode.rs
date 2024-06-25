/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::{runtime::Variable, Context};
use unicode_security::MixedScript;

pub fn fn_is_ascii<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
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

pub fn fn_has_zwsp<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
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

pub fn fn_has_obscured<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
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

pub fn fn_cure_text<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    decancer::cure(v[0].to_string().as_ref(), decancer::Options::default())
        .map(String::from)
        .unwrap_or_default()
        .into()
}

pub fn fn_unicode_skeleton<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    unicode_security::skeleton(v[0].to_string().as_ref())
        .collect::<String>()
        .into()
}

pub fn fn_is_single_script<'x>(_: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    let text = v[0].to_string();
    if !text.is_empty() {
        text.as_ref().is_single_script()
    } else {
        true
    }
    .into()
}
