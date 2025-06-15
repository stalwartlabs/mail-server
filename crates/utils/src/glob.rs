/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, AHashSet};

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

    pub fn try_compile(pattern: &str, to_lower: bool) -> Result<Self, String> {
        // Detect if the key is a glob pattern
        let mut last_ch = '\0';
        let mut has_escape = false;
        let mut is_glob = false;
        for ch in pattern.chars() {
            match ch {
                '\\' => {
                    has_escape = true;
                }
                '*' | '?' if last_ch != '\\' => {
                    is_glob = true;
                }
                _ => {}
            }

            last_ch = ch;
        }

        if is_glob {
            Ok(GlobPattern::compile(pattern, to_lower))
        } else {
            Err(if has_escape {
                pattern.replace('\\', "")
            } else {
                pattern.to_string()
            })
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

#[derive(Debug, Clone, Default)]
pub struct GlobSet {
    entries: AHashSet<String>,
    patterns: Vec<GlobPattern>,
}

#[derive(Debug, Clone)]
pub struct GlobMap<V> {
    entries: AHashMap<String, V>,
    patterns: Vec<(GlobPattern, V)>,
}

impl GlobSet {
    pub fn new() -> Self {
        GlobSet::default()
    }

    pub fn insert(&mut self, pattern: &str) {
        match GlobPattern::try_compile(pattern, false) {
            Ok(glob) => {
                self.patterns.push(glob);
            }
            Err(entry) => {
                self.entries.insert(entry);
            }
        }
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains(key) || self.patterns.iter().any(|pattern| pattern.matches(key))
    }
}

impl<V> GlobMap<V> {
    pub fn new() -> Self {
        GlobMap {
            entries: AHashMap::new(),
            patterns: Vec::new(),
        }
    }

    pub fn insert(&mut self, pattern: &str, value: V) {
        match GlobPattern::try_compile(pattern, false) {
            Ok(glob) => {
                self.patterns.push((glob, value));
            }
            Err(entry) => {
                self.entries.insert(entry, value);
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.entries.get(key).or_else(|| {
            self.patterns
                .iter()
                .find_map(|(pattern, value)| pattern.matches(key).then_some(value))
        })
    }
}

impl<V> Default for GlobMap<V> {
    fn default() -> Self {
        GlobMap::new()
    }
}
