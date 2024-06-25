/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobPattern {
    pattern: Vec<PatternChar>,
    to_lower: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternChar {
    WildcardMany { num: usize, match_pos: usize },
    WildcardSingle { match_pos: usize },
    Char { char: char, match_pos: usize },
}

impl GlobPattern {
    pub fn compile(pattern: &str, to_lower: bool) -> Self {
        let mut chars = Vec::new();
        let mut is_escaped = false;
        let mut str = pattern.chars().peekable();

        while let Some(char) = str.next() {
            match char {
                '*' if !is_escaped => {
                    let mut num = 1;
                    while let Some('*') = str.peek() {
                        num += 1;
                        str.next();
                    }
                    chars.push(PatternChar::WildcardMany { num, match_pos: 0 });
                }
                '?' if !is_escaped => {
                    chars.push(PatternChar::WildcardSingle { match_pos: 0 });
                }
                '\\' if !is_escaped => {
                    is_escaped = true;
                    continue;
                }
                _ => {
                    if is_escaped {
                        is_escaped = false;
                    }
                    if to_lower && char.is_uppercase() {
                        for char in char.to_lowercase() {
                            chars.push(PatternChar::Char { char, match_pos: 0 });
                        }
                    } else {
                        chars.push(PatternChar::Char { char, match_pos: 0 });
                    }
                }
            }
        }

        GlobPattern {
            pattern: chars,
            to_lower,
        }
    }

    // Credits: Algorithm ported from https://research.swtch.com/glob
    pub fn matches(&self, value: &str) -> bool {
        let value = if self.to_lower {
            value.to_lowercase().chars().collect::<Vec<_>>()
        } else {
            value.chars().collect::<Vec<_>>()
        };

        let mut px = 0;
        let mut nx = 0;
        let mut next_px = 0;
        let mut next_nx = 0;

        while px < self.pattern.len() || nx < value.len() {
            match self.pattern.get(px) {
                Some(PatternChar::Char { char, .. }) => {
                    if matches!(value.get(nx), Some(nc) if nc == char ) {
                        px += 1;
                        nx += 1;
                        continue;
                    }
                }
                Some(PatternChar::WildcardSingle { .. }) => {
                    if nx < value.len() {
                        px += 1;
                        nx += 1;
                        continue;
                    }
                }
                Some(PatternChar::WildcardMany { .. }) => {
                    next_px = px;
                    next_nx = nx + 1;
                    px += 1;
                    continue;
                }
                _ => (),
            }
            if 0 < next_nx && next_nx <= value.len() {
                px = next_px;
                nx = next_nx;
                continue;
            }
            return false;
        }
        true
    }
}
