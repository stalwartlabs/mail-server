use std::collections::{HashMap, HashSet};

pub fn replace_tags(
    pattern: &str,
    tag_start: char,
    tag_end: char,
    patterns: &HashMap<String, String>,
) -> String {
    //print!("replacing {} ", pattern);
    let mut result = String::with_capacity(pattern.len());
    let mut chars = fix_broken_regex(pattern.trim()).chars();
    let mut tag_pre = String::new();
    let mut tag_inter = String::new();
    let mut tag_post = String::new();
    let mut is_adjacent = false;

    'outer: while let Some(ch) = chars.next() {
        if ch == tag_start {
            let mut buf = String::new();
            for ch in chars.by_ref() {
                if ch == tag_end {
                    break;
                } else if ch.is_ascii_alphanumeric() || ch.is_ascii_whitespace() {
                    buf.push(ch);
                } else {
                    result.push(tag_start);
                    result.push_str(&buf);
                    result.push(ch);
                    continue 'outer;
                }
            }
            if let Some(pattern) = patterns.get(&buf) {
                if buf.starts_with("pre ") {
                    tag_pre = pattern.to_string();
                } else if buf.starts_with("inter ") {
                    tag_inter = pattern.to_string();
                } else if buf.starts_with("post ") {
                    tag_post = pattern.to_string();
                } else {
                    if !tag_pre.is_empty() {
                        result.push_str(&tag_pre);
                    }
                    if !tag_inter.is_empty() && is_adjacent {
                        result.push_str(&tag_inter);
                    }
                    result.push_str(pattern);
                    if !tag_post.is_empty() {
                        result.push_str(&tag_post);
                    }
                    is_adjacent = true;
                }
            } else {
                eprintln!("Warning: Unknown tag {}", buf);
            }
        } else {
            result.push(ch);
            is_adjacent = false;
        }
    }

    //println!("to {}", result);

    result
}

pub fn fix_broken_regex(value: &str) -> &str {
    match value {
        r"/[\042\223\224\262\263\271]{2}\S{0,16}[\042\223\224\262\263\271]{2}/" => {
            //r#"[\"\u{93}\u{94}\u{B2}\u{B3}\u{B9}]{2}\S{0,16}[\"\u{93}\u{94}\u{B2}\u{B3}\u{B9}]{2}"#
            r"/[\x22\x93\x94\xB2\xB3\xB9]{2}\S{0,16}[\x22\x93\x94\xB2\xB3\xB9]{2}/"
        }
        r"/\b_{0,3}d[_\W]?[i1!|l\xEC-\xEF][_\W]?d[_\W]?r[_\W][e3\xE8-\xEB[_\W]?xx?_{0,3}\b/i" => {
            r"/\b_{0,3}d[_\W]?[i1!|l\xEC-\xEF][_\W]?d[_\W]?r[_\W][e3\xE8-\xEB][_\W]?xx?_{0,3}\b/i"
        }
        r#"/<!--(?:\s{1,10}[-\w'"]{1,40}){100}/im"# => r#"/<!--(?:\s{1,10}[-\w'"]{1,40}){5}/im"#,
        r"/\015/" => r"/\x0D/",
        r"/[({[<][. ]*(?-i:\xbc\xba[. ]*\xc0\xce[. ]*)?(?-i:\xb1\xa4(?:[. ]*|[\x00-\x7f]{0,3})\xb0\xed|\xc1\xa4[. ]*\xba\xb8|\xc8\xab[. ]*\xba\xb8)[. ]*[)}\]>]/" => {
            r"/[\(\{\[\<][. ]*(?-i:\xbc\xba[. ]*\xc0\xce[. ]*)?(?-i:\xb1\xa4(?:[. ]*|[\x00-\x7f]{0,3})\xb0\xed|\xc1\xa4[. ]*\xba\xb8|\xc8\xab[. ]*\xba\xb8)[. ]*[\)\}\]\>]/"
        }
        _ => value,
    }
}

pub fn import_regex(value: &str) -> (String, HashSet<String>) {
    // Obtain separator
    let mut iter = value.chars().peekable();
    let separator = match iter.next() {
        Some('/') => Some('/'),
        Some('m') => iter.next().map(|ch| if ch == '{' { '}' } else { ch }),
        _ => None,
    }
    .unwrap_or(char::from(0));
    let mut regex = String::with_capacity(value.len());
    let mut flags = String::new();

    let mut variables = HashSet::new();
    let mut variable_buf = String::new();
    let mut in_variable = false;

    // Obtain regex
    let mut found_separator = false;
    while let Some(mut ch) = iter.next() {
        if ch == '%' && matches!(iter.peek(), Some('{')) {
            ch = '$';
            in_variable = true;
        } else if in_variable {
            match ch {
                '{' => {}
                '}' => {
                    if !variable_buf.is_empty() {
                        variables.insert(variable_buf.clone());
                        variable_buf.clear();
                    }
                    in_variable = false;
                }
                _ => {
                    variable_buf.push(ch);
                }
            }
        }

        if ch == separator {
            if !found_separator {
                found_separator = true;
            } else {
                regex.push(ch);
                regex.push_str(&flags);
                flags.clear();
            }
        } else if !found_separator {
            regex.push(ch);
        } else {
            flags.push(ch);
        }
    }

    (
        if !flags.is_empty() {
            format!("(?{flags}){regex}")
        } else {
            regex
        },
        variables,
    )
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    #[test]
    fn import_regex() {
        for (expr, result, vars) in [
            (
                r"m{<img\b[^>]{0,100}\ssrc=.?https?://[^>]{6,80}(?:\?[^>]{8}|[^a-z](?![a-f]{3}|20\d\d[01]\d[0-3]\d)[0-9a-f]{8})}i",
                r"(?i)<img\b[^>]{0,100}\ssrc=.?https?://[^>]{6,80}(?:\?[^>]{8}|[^a-z](?![a-f]{3}|20\d\d[01]\d[0-3]\d)[0-9a-f]{8})",
                vec![],
            ),
            (r"/\bhoodia\b/i", r"(?i)\bhoodia\b", vec![]),
            (r"/\bCurrent Price:/", r"\bCurrent Price:", vec![]),
            (
                r"m|^https?://storage\.cloud\.google\.com/.{4,128}\#%{GB_TO_ADDR}|i",
                r"(?i)^https?://storage\.cloud\.google\.com/.{4,128}\#${GB_TO_ADDR}",
                vec!["GB_TO_ADDR"],
            ),
        ] {
            let (regex, regex_vars) = super::import_regex(expr);
            assert_eq!(regex, result);
            assert_eq!(
                HashSet::from_iter(vars.iter().map(|s| s.to_string())),
                regex_vars
            );
        }
    }
}
