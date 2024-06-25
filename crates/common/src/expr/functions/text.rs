/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::expr::Variable;

pub(crate) fn fn_trim(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| match s {
        Cow::Borrowed(s) => Variable::from(s.trim()),
        Cow::Owned(s) => Variable::from(s.trim().to_string()),
    })
}

pub(crate) fn fn_trim_end(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| match s {
        Cow::Borrowed(s) => Variable::from(s.trim_end()),
        Cow::Owned(s) => Variable::from(s.trim_end().to_string()),
    })
}

pub(crate) fn fn_trim_start(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| match s {
        Cow::Borrowed(s) => Variable::from(s.trim_start()),
        Cow::Owned(s) => Variable::from(s.trim_start().to_string()),
    })
}

pub(crate) fn fn_len(v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.len(),
        Variable::Array(a) => a.len(),
        v => v.to_string().len(),
    }
    .into()
}

pub(crate) fn fn_to_lowercase(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| Variable::from(s.to_lowercase()))
}

pub(crate) fn fn_to_uppercase(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| Variable::from(s.to_uppercase()))
}

pub(crate) fn fn_is_uppercase(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| {
        s.chars()
            .filter(|c| c.is_alphabetic())
            .all(|c| c.is_uppercase())
            .into()
    })
}

pub(crate) fn fn_is_lowercase(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| {
        s.chars()
            .filter(|c| c.is_alphabetic())
            .all(|c| c.is_lowercase())
            .into()
    })
}

pub(crate) fn fn_has_digits(mut v: Vec<Variable>) -> Variable {
    v.remove(0)
        .transform(|s| s.chars().any(|c| c.is_ascii_digit()).into())
}

pub(crate) fn fn_split_words(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .split_whitespace()
        .filter(|word| word.chars().all(|c| c.is_alphanumeric()))
        .map(|word| Variable::from(word.to_string()))
        .collect::<Vec<_>>()
        .into()
}

pub(crate) fn fn_count_spaces(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_ref()
        .chars()
        .filter(|c| c.is_whitespace())
        .count()
        .into()
}

pub(crate) fn fn_count_uppercase(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_ref()
        .chars()
        .filter(|c| c.is_alphabetic() && c.is_uppercase())
        .count()
        .into()
}

pub(crate) fn fn_count_lowercase(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_ref()
        .chars()
        .filter(|c| c.is_alphabetic() && c.is_lowercase())
        .count()
        .into()
}

pub(crate) fn fn_count_chars(v: Vec<Variable>) -> Variable {
    v[0].to_string().as_ref().chars().count().into()
}

pub(crate) fn fn_eq_ignore_case(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .eq_ignore_ascii_case(v[1].to_string().as_ref())
        .into()
}

pub(crate) fn fn_contains(v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.contains(v[1].to_string().as_ref()),
        Variable::Array(arr) => arr.contains(&v[1]),
        val => val.to_string().contains(v[1].to_string().as_ref()),
    }
    .into()
}

pub(crate) fn fn_contains_ignore_case(v: Vec<Variable>) -> Variable {
    let needle = v[1].to_string();
    match &v[0] {
        Variable::String(s) => s.to_lowercase().contains(&needle.to_lowercase()),
        Variable::Array(arr) => arr.iter().any(|v| match v {
            Variable::String(s) => s.eq_ignore_ascii_case(needle.as_ref()),
            _ => false,
        }),
        val => val.to_string().contains(needle.as_ref()),
    }
    .into()
}

pub(crate) fn fn_starts_with(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .starts_with(v[1].to_string().as_ref())
        .into()
}

pub(crate) fn fn_ends_with(v: Vec<Variable>) -> Variable {
    v[0].to_string().ends_with(v[1].to_string().as_ref()).into()
}

pub(crate) fn fn_lines(mut v: Vec<Variable>) -> Variable {
    match v.remove(0) {
        Variable::String(s) => s
            .lines()
            .map(|s| Variable::from(s.to_string()))
            .collect::<Vec<_>>()
            .into(),
        val => val,
    }
}

pub(crate) fn fn_substring(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .chars()
        .skip(v[1].to_usize().unwrap_or_default())
        .take(v[2].to_usize().unwrap_or_default())
        .collect::<String>()
        .into()
}

pub(crate) fn fn_strip_prefix(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap();
    let prefix = v.next().unwrap().into_string();

    value.transform(|s| match s {
        Cow::Borrowed(s) => s
            .strip_prefix(prefix.as_ref())
            .map(Variable::from)
            .unwrap_or_default(),
        Cow::Owned(s) => s
            .strip_prefix(prefix.as_ref())
            .map(|s| Variable::from(s.to_string()))
            .unwrap_or_default(),
    })
}

pub(crate) fn fn_strip_suffix(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap();
    let suffix = v.next().unwrap().into_string();

    value.transform(|s| match s {
        Cow::Borrowed(s) => s
            .strip_suffix(suffix.as_ref())
            .map(Variable::from)
            .unwrap_or_default(),
        Cow::Owned(s) => s
            .strip_suffix(suffix.as_ref())
            .map(|s| Variable::from(s.to_string()))
            .unwrap_or_default(),
    })
}

pub(crate) fn fn_split(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let arg = v.next().unwrap().into_string();

    match value {
        Cow::Borrowed(s) => s
            .split(arg.as_ref())
            .map(Variable::from)
            .collect::<Vec<_>>()
            .into(),
        Cow::Owned(s) => s
            .split(arg.as_ref())
            .map(|s| Variable::from(s.to_string()))
            .collect::<Vec<_>>()
            .into(),
    }
}

pub(crate) fn fn_rsplit(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let arg = v.next().unwrap().into_string();

    match value {
        Cow::Borrowed(s) => s
            .rsplit(arg.as_ref())
            .map(Variable::from)
            .collect::<Vec<_>>()
            .into(),
        Cow::Owned(s) => s
            .rsplit(arg.as_ref())
            .map(|s| Variable::from(s.to_string()))
            .collect::<Vec<_>>()
            .into(),
    }
}

pub(crate) fn fn_split_once(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let arg = v.next().unwrap().into_string();

    match value {
        Cow::Borrowed(s) => s
            .split_once(arg.as_ref())
            .map(|(a, b)| Variable::Array(vec![Variable::from(a), Variable::from(b)]))
            .unwrap_or_default(),
        Cow::Owned(s) => s
            .split_once(arg.as_ref())
            .map(|(a, b)| {
                Variable::Array(vec![
                    Variable::from(a.to_string()),
                    Variable::from(b.to_string()),
                ])
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn fn_rsplit_once(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let arg = v.next().unwrap().into_string();

    match value {
        Cow::Borrowed(s) => s
            .rsplit_once(arg.as_ref())
            .map(|(a, b)| Variable::Array(vec![Variable::from(a), Variable::from(b)]))
            .unwrap_or_default(),
        Cow::Owned(s) => s
            .rsplit_once(arg.as_ref())
            .map(|(a, b)| {
                Variable::Array(vec![
                    Variable::from(a.to_string()),
                    Variable::from(b.to_string()),
                ])
            })
            .unwrap_or_default(),
    }
}
