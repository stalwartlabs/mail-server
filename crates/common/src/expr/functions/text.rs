/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::{CompactString, ToCompactString, format_compact};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::expr::{StringCow, Variable};

pub(crate) fn fn_trim(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| match s {
        StringCow::Borrowed(s) => Variable::from(s.trim()),
        StringCow::Owned(s) => Variable::from(s.trim().to_compact_string()),
    })
}

pub(crate) fn fn_trim_end(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| match s {
        StringCow::Borrowed(s) => Variable::from(s.trim_end()),
        StringCow::Owned(s) => Variable::from(s.trim_end().to_compact_string()),
    })
}

pub(crate) fn fn_trim_start(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| match s {
        StringCow::Borrowed(s) => Variable::from(s.trim_start()),
        StringCow::Owned(s) => Variable::from(s.trim_start().to_compact_string()),
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
    v.remove(0)
        .transform(|s| Variable::from(CompactString::from_str_to_lowercase(s.as_str())))
}

pub(crate) fn fn_to_uppercase(mut v: Vec<Variable>) -> Variable {
    v.remove(0)
        .transform(|s| Variable::from(CompactString::from_str_to_uppercase(s.as_str())))
}

pub(crate) fn fn_is_uppercase(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| {
        s.as_str()
            .chars()
            .filter(|c| c.is_alphabetic())
            .all(|c| c.is_uppercase())
            .into()
    })
}

pub(crate) fn fn_is_lowercase(mut v: Vec<Variable>) -> Variable {
    v.remove(0).transform(|s| {
        s.as_str()
            .chars()
            .filter(|c| c.is_alphabetic())
            .all(|c| c.is_lowercase())
            .into()
    })
}

pub(crate) fn fn_has_digits(mut v: Vec<Variable>) -> Variable {
    v.remove(0)
        .transform(|s| s.as_str().chars().any(|c| c.is_ascii_digit()).into())
}

pub(crate) fn fn_split_words(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .split_whitespace()
        .filter(|word| word.chars().all(|c| c.is_alphanumeric()))
        .map(|word| Variable::from(CompactString::new(word)))
        .collect::<Vec<_>>()
        .into()
}

pub(crate) fn fn_count_spaces(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .chars()
        .filter(|c| c.is_whitespace())
        .count()
        .into()
}

pub(crate) fn fn_count_uppercase(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .chars()
        .filter(|c| c.is_alphabetic() && c.is_uppercase())
        .count()
        .into()
}

pub(crate) fn fn_count_lowercase(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .chars()
        .filter(|c| c.is_alphabetic() && c.is_lowercase())
        .count()
        .into()
}

pub(crate) fn fn_count_chars(v: Vec<Variable>) -> Variable {
    v[0].to_string().as_str().chars().count().into()
}

pub(crate) fn fn_eq_ignore_case(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .eq_ignore_ascii_case(v[1].to_string().as_str())
        .into()
}

pub(crate) fn fn_contains(v: Vec<Variable>) -> Variable {
    match &v[0] {
        Variable::String(s) => s.as_str().contains(v[1].to_string().as_str()),
        Variable::Array(arr) => arr.contains(&v[1]),
        val => val.to_string().as_str().contains(v[1].to_string().as_str()),
    }
    .into()
}

pub(crate) fn fn_contains_ignore_case(v: Vec<Variable>) -> Variable {
    let needle = v[1].to_string();
    match &v[0] {
        Variable::String(s) => s
            .as_str()
            .to_lowercase()
            .contains(&needle.as_str().to_lowercase()),
        Variable::Array(arr) => arr.iter().any(|v| match v {
            Variable::String(s) => s.as_str().eq_ignore_ascii_case(needle.as_str()),
            _ => false,
        }),
        val => val.to_string().as_str().contains(needle.as_str()),
    }
    .into()
}

pub(crate) fn fn_starts_with(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .starts_with(v[1].to_string().as_str())
        .into()
}

pub(crate) fn fn_ends_with(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .ends_with(v[1].to_string().as_str())
        .into()
}

pub(crate) fn fn_lines(mut v: Vec<Variable>) -> Variable {
    match v.remove(0) {
        Variable::String(s) => s
            .as_str()
            .lines()
            .map(|s| Variable::from(CompactString::new(s)))
            .collect::<Vec<_>>()
            .into(),
        val => val,
    }
}

pub(crate) fn fn_substring(v: Vec<Variable>) -> Variable {
    v[0].to_string()
        .as_str()
        .chars()
        .skip(v[1].to_usize().unwrap_or_default())
        .take(v[2].to_usize().unwrap_or_default())
        .collect::<CompactString>()
        .into()
}

pub(crate) fn fn_strip_prefix(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap();
    let prefix = v.next().unwrap().into_string();

    value.transform(|s| match s {
        StringCow::Borrowed(s) => s
            .strip_prefix(prefix.as_str())
            .map(Variable::from)
            .unwrap_or_default(),
        StringCow::Owned(s) => s
            .strip_prefix(prefix.as_str())
            .map(|s| Variable::from(CompactString::new(s)))
            .unwrap_or_default(),
    })
}

pub(crate) fn fn_strip_suffix(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap();
    let suffix = v.next().unwrap().into_string();

    value.transform(|s| match s {
        StringCow::Borrowed(s) => s
            .strip_suffix(suffix.as_str())
            .map(Variable::from)
            .unwrap_or_default(),
        StringCow::Owned(s) => s
            .strip_suffix(suffix.as_str())
            .map(|s| Variable::from(CompactString::new(s)))
            .unwrap_or_default(),
    })
}

pub(crate) fn fn_split(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let arg = v.next().unwrap().into_string();

    match value {
        StringCow::Borrowed(s) => s
            .split(arg.as_str())
            .map(Variable::from)
            .collect::<Vec<_>>()
            .into(),
        StringCow::Owned(s) => s
            .split(arg.as_str())
            .map(|s| Variable::from(CompactString::new(s)))
            .collect::<Vec<_>>()
            .into(),
    }
}

pub(crate) fn fn_rsplit(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let arg = v.next().unwrap().into_string();

    match value {
        StringCow::Borrowed(s) => s
            .rsplit(arg.as_str())
            .map(Variable::from)
            .collect::<Vec<_>>()
            .into(),
        StringCow::Owned(s) => s
            .rsplit(arg.as_str())
            .map(|s| Variable::from(CompactString::new(s)))
            .collect::<Vec<_>>()
            .into(),
    }
}

pub(crate) fn fn_split_n(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let arg = v.next().unwrap().into_string();
    let num = v.next().unwrap().to_integer().unwrap_or_default() as usize;

    fn split_n<'x, 'y>(s: &'x str, arg: &'y str, num: usize, mut f: impl FnMut(&'x str)) {
        let mut s = s;
        for _ in 0..num {
            if let Some((a, b)) = s.split_once(arg) {
                f(a);
                s = b;
            } else {
                break;
            }
        }
        f(s);
    }

    let mut result = Vec::new();
    match value {
        StringCow::Borrowed(s) => split_n(s, arg.as_str(), num, |s| result.push(Variable::from(s))),
        StringCow::Owned(s) => split_n(&s, arg.as_str(), num, |s| {
            result.push(Variable::from(CompactString::new(s)))
        }),
    }

    result.into()
}

pub(crate) fn fn_split_once(v: Vec<Variable>) -> Variable {
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let arg = v.next().unwrap().into_string();

    match value {
        StringCow::Borrowed(s) => s
            .split_once(arg.as_str())
            .map(|(a, b)| Variable::Array(vec![Variable::from(a), Variable::from(b)]))
            .unwrap_or_default(),
        StringCow::Owned(s) => s
            .split_once(arg.as_str())
            .map(|(a, b)| {
                Variable::Array(vec![
                    Variable::from(CompactString::new(a)),
                    Variable::from(CompactString::new(b)),
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
        StringCow::Borrowed(s) => s
            .rsplit_once(arg.as_str())
            .map(|(a, b)| Variable::Array(vec![Variable::from(a), Variable::from(b)]))
            .unwrap_or_default(),
        StringCow::Owned(s) => s
            .rsplit_once(arg.as_str())
            .map(|(a, b)| {
                Variable::Array(vec![
                    Variable::from(CompactString::new(a)),
                    Variable::from(CompactString::new(b)),
                ])
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn fn_hash(v: Vec<Variable>) -> Variable {
    use sha1::Digest;
    let mut v = v.into_iter();
    let value = v.next().unwrap().into_string();
    let algo = v.next().unwrap().into_string();

    match algo.as_str() {
        "md5" => format_compact!("{:x}", md5::compute(value.as_bytes())).into(),
        "sha1" => {
            let mut hasher = Sha1::new();
            hasher.update(value.as_bytes());
            format_compact!("{:x}", hasher.finalize()).into()
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            format_compact!("{:x}", hasher.finalize()).into()
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(value.as_bytes());
            format_compact!("{:x}", hasher.finalize()).into()
        }
        _ => Variable::default(),
    }
}
