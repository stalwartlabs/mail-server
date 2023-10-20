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

use std::{
    collections::{btree_map::Entry, BTreeMap},
    iter::Peekable,
    str::Chars,
};

use super::{Config, Result};
use std::fmt::Write;

const MAX_NEST_LEVEL: usize = 10;

// Simple TOML parser for Stalwart Mail Server configuration files.

impl Config {
    pub fn new(toml: &str) -> Result<Self> {
        let mut config = Config::default();
        config.parse(toml)?;
        Ok(config)
    }

    pub fn parse(&mut self, toml: &str) -> Result<()> {
        let mut parser = TomlParser::new(&mut self.keys, toml);
        let mut table_name = String::new();
        let mut last_array_name = String::new();
        let mut last_array_pos = 0;

        while parser.seek_next_char() {
            match parser.peek_char()? {
                '[' => {
                    parser.next_char(true, false)?;
                    table_name.clear();
                    let mut is_array = match parser.next_char(true, false)? {
                        '[' => true,
                        ch => {
                            table_name.push(ch);
                            false
                        }
                    };
                    let mut in_quote = false;
                    let mut last_ch = char::from(0);
                    loop {
                        let ch = parser.next_char(!in_quote, false)?;
                        match ch {
                            '\"' if !in_quote || last_ch != '\\' => {
                                in_quote = !in_quote;
                            }
                            '\\' if in_quote => (),
                            ']' if !in_quote => {
                                if table_name.is_empty() {
                                    return Err(format!(
                                        "Empty table name at line {}.",
                                        parser.line
                                    ));
                                }
                                if is_array {
                                    if table_name == last_array_name {
                                        last_array_pos += 1;
                                    } else {
                                        last_array_pos = 0;
                                        last_array_name = table_name.to_string();
                                    }
                                    is_array = false;
                                    write!(table_name, ".{last_array_pos:04}").ok();
                                } else {
                                    break;
                                }
                            }
                            _ => {
                                if !in_quote {
                                    if ch.is_alphanumeric() || ['.', '-', '_'].contains(&ch) {
                                        table_name.push(ch.to_ascii_lowercase());
                                    } else {
                                        return Err(format!(
                                            "Unexpected character {:?} at line {}.",
                                            ch, parser.line
                                        ));
                                    }
                                } else {
                                    table_name.push(ch);
                                }
                            }
                        }
                        last_ch = ch;
                    }
                    parser.skip_line();
                }
                'a'..='z' | 'A'..='Z' | '0'..='9' | '\"' => {
                    let key = parser.key(if !table_name.is_empty() {
                        format!("{table_name}.")
                    } else {
                        String::with_capacity(10)
                    })?;
                    parser.value(key, &['\n'], 0)?;
                }
                '#' => {
                    parser.skip_line();
                }
                ch => {
                    let ch = *ch;
                    return Err(format!(
                        "Unexpected character {:?} at line {}.",
                        ch, parser.line
                    ));
                }
            }
        }

        Ok(())
    }
}

struct TomlParser<'x, 'y> {
    keys: &'y mut BTreeMap<String, String>,
    iter: Peekable<Chars<'x>>,
    line: usize,
}

impl<'x, 'y> TomlParser<'x, 'y> {
    fn new(keys: &'y mut BTreeMap<String, String>, toml: &'x str) -> Self {
        Self {
            keys,
            iter: toml.chars().peekable(),
            line: 1,
        }
    }

    fn seek_next_char(&mut self) -> bool {
        while let Some(ch) = self.iter.peek() {
            match ch {
                '\n' => {
                    self.iter.next();
                    self.line += 1;
                }
                '\r' | ' ' | '\t' => {
                    self.iter.next();
                }
                '#' => {
                    self.skip_line();
                }
                _ => {
                    return true;
                }
            }
        }

        false
    }

    fn peek_char(&mut self) -> Result<&char> {
        self.iter.peek().ok_or_else(|| "".to_string())
    }

    fn next_char(&mut self, skip_wsp: bool, allow_lf: bool) -> Result<char> {
        for ch in &mut self.iter {
            match ch {
                '\r' => (),
                ' ' | '\t' if skip_wsp => (),
                '\n' => {
                    return if allow_lf {
                        self.line += 1;
                        Ok(ch)
                    } else {
                        Err(format!("Unexpected end of line at line: {}", self.line))
                    };
                }
                _ => {
                    return Ok(ch);
                }
            }
        }
        Err(format!("Unexpected EOF at line: {}", self.line))
    }

    fn skip_line(&mut self) {
        for ch in &mut self.iter {
            if ch == '\n' {
                self.line += 1;
                break;
            }
        }
    }

    #[allow(clippy::while_let_on_iterator)]
    fn key(&mut self, mut key: String) -> Result<String> {
        while let Some(ch) = self.iter.next() {
            match ch {
                '=' => {
                    if !key.is_empty() {
                        return Ok(key);
                    } else {
                        return Err(format!("Empty key at line: {}", self.line));
                    }
                }
                'a'..='z' | '.' | 'A'..='Z' | '0'..='9' | '_' | '-' => {
                    key.push(ch);
                }
                '\"' => {
                    let mut last_ch = char::from(0);
                    while let Some(ch) = self.iter.next() {
                        match ch {
                            '\\' => (),
                            '\"' if last_ch != '\\' => {
                                break;
                            }
                            '\n' => {
                                return Err(format!(
                                    "Unexpected end of line at line: {}",
                                    self.line
                                ));
                            }
                            _ => {
                                key.push(ch);
                            }
                        }
                        last_ch = ch;
                    }
                }
                ' ' | '\t' | '\r' => (),
                '\n' => {
                    return Err(format!("Unexpected end of line at line: {}", self.line));
                }
                _ => {
                    return Err(format!(
                        "Unexpected character {:?} found in key at line {}.",
                        ch, self.line
                    ));
                }
            }
        }
        Err(format!("Unexpected EOF at line: {}", self.line))
    }

    fn value(&mut self, key: String, stop_chars: &[char], nest_level: usize) -> Result<char> {
        if nest_level == MAX_NEST_LEVEL {
            return Err(format!("Too many nested structures at line {}.", self.line));
        }
        match self.next_char(true, false)? {
            '[' => {
                let mut array_pos = 0;
                self.seek_next_char();
                loop {
                    match self.value(
                        format!("{key}.{array_pos:04}"),
                        &[',', ']'],
                        nest_level + 1,
                    )? {
                        ',' => {
                            self.seek_next_char();
                            array_pos += 1;
                        }
                        ']' => break,
                        ch => {
                            return Err(format!(
                                "Unexpected character {:?} found in array for property {:?} at line {}.",
                                ch, key, self.line
                            ));
                        }
                    }
                }
            }
            '{' => loop {
                let sub_key = self.key(format!("{key}."))?;
                self.seek_next_char();

                match self.value(sub_key, &[',', '}'], nest_level + 1)? {
                    ',' => {
                        self.seek_next_char();
                    }
                    '}' => break,
                    ch => {
                        return Err(format!(
                                "Unexpected character {:?} found in inline table for property {:?} at line {}.",
                                ch, key, self.line
                            ));
                    }
                }
            },
            qch @ ('\'' | '\"') => {
                let mut value = String::new();
                if matches!(self.iter.peek(), Some(ch) if ch == &qch) {
                    self.iter.next();
                    if matches!(self.iter.peek(), Some(ch) if ch == &qch) {
                        self.iter.next();
                        if matches!(self.iter.peek(), Some(ch) if ch == &'\n') {
                            self.iter.next();
                            self.line += 1;
                        }

                        let mut last_ch = char::from(0);
                        let mut prev_last_ch = char::from(0);
                        loop {
                            let ch = self.next_char(false, true)?;
                            if !(ch == qch && last_ch == qch && prev_last_ch == qch) {
                                value.push(ch);
                                prev_last_ch = last_ch;
                                last_ch = ch;
                            } else {
                                value.truncate(value.len() - 2);
                                break;
                            }
                        }
                    }
                } else {
                    let mut last_ch = char::from(0);

                    loop {
                        let ch = self.next_char(false, true)?;
                        match ch {
                            '\\' if last_ch != '\\' => (),
                            't' if last_ch == '\\' => {
                                value.push('\t');
                            }
                            'r' if last_ch == '\\' => {
                                value.push('\r');
                            }
                            'n' if last_ch == '\\' => {
                                value.push('\n');
                            }
                            ch => {
                                if ch != qch || last_ch == '\\' {
                                    value.push(ch);
                                } else {
                                    break;
                                }
                            }
                        }
                        last_ch = ch;
                    }
                }

                self.insert_key(key, value)?;
            }
            ch if ch.is_alphanumeric() || ['.', '+', '-'].contains(&ch) => {
                let mut value = String::with_capacity(4);
                value.push(ch);
                while let Some(ch) = self.iter.peek() {
                    if ch.is_alphanumeric() || ['.', '+', '-'].contains(ch) {
                        value.push(self.next_char(true, false)?);
                    } else {
                        break;
                    }
                }
                self.insert_key(key, value)?;
            }
            '!' => {
                let mut value = String::with_capacity(4);
                while let Some(ch) = self.iter.peek() {
                    if ch.is_alphanumeric() || ['_', '-'].contains(ch) {
                        value.push(self.next_char(true, false)?);
                    } else {
                        break;
                    }
                }
                let value = match std::env::var(value.as_str()) {
                    Ok(value) => value,
                    Err(_) => {
                        tracing::warn!("Failed to get environment variable {value:?}");
                        String::new()
                    }
                };
                self.insert_key(key, value)?;
            }
            ch => {
                return if stop_chars.contains(&ch) {
                    Ok(ch)
                } else {
                    Err(format!(
                        "Expected {:?} but found {:?} in value at line {}.",
                        stop_chars, ch, self.line
                    ))
                }
            }
        }

        loop {
            match self.next_char(true, true)? {
                '#' => {
                    self.skip_line();
                    if stop_chars.contains(&'\n') {
                        return Ok('\n');
                    }
                }
                ch if stop_chars.contains(&ch) => {
                    return Ok(ch);
                }
                '\n' if !stop_chars.contains(&'\n') => (),
                ch => {
                    return Err(format!(
                        "Expected {:?} but found {:?} in value at line {}.",
                        stop_chars, ch, self.line
                    ));
                }
            }
        }
    }

    fn insert_key(&mut self, key: String, mut value: String) -> Result<()> {
        match self.keys.entry(key) {
            Entry::Vacant(e) => {
                value.shrink_to_fit();
                e.insert(value);
                Ok(())
            }
            Entry::Occupied(e) => Err(format!(
                "Duplicate key {:?} at line {}.",
                e.key(),
                self.line
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::PathBuf};

    use crate::config::Config;

    #[test]
    fn toml_parse() {
        let file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
            .join("tests")
            .join("resources")
            .join("smtp")
            .join("config")
            .join("toml-parser.toml");

        let mut config = Config::default();
        config.parse(&fs::read_to_string(file).unwrap()).unwrap();
        let expected = BTreeMap::from_iter([
            ("arrays.colors.0000".to_string(), "red".to_string()),
            ("arrays.colors.0001".to_string(), "yellow".to_string()),
            ("arrays.colors.0002".to_string(), "green".to_string()),
            (
                "arrays.contributors.0000".to_string(),
                "Foo Bar <foo@example.com>".to_string(),
            ),
            (
                "arrays.contributors.0001.email".to_string(),
                "bazqux@example.com".to_string(),
            ),
            (
                "arrays.contributors.0001.name".to_string(),
                "Baz Qux".to_string(),
            ),
            (
                "arrays.contributors.0001.url".to_string(),
                "https://example.com/bazqux".to_string(),
            ),
            ("arrays.integers.0000".to_string(), "1".to_string()),
            ("arrays.integers.0001".to_string(), "2".to_string()),
            ("arrays.integers.0002".to_string(), "3".to_string()),
            ("arrays.integers2.0000".to_string(), "1".to_string()),
            ("arrays.integers2.0001".to_string(), "2".to_string()),
            ("arrays.integers2.0002".to_string(), "3".to_string()),
            ("arrays.integers3.0000".to_string(), "4".to_string()),
            ("arrays.integers3.0001".to_string(), "5".to_string()),
            (
                "arrays.nested_arrays_of_ints.0000.0000".to_string(),
                "1".to_string(),
            ),
            (
                "arrays.nested_arrays_of_ints.0000.0001".to_string(),
                "2".to_string(),
            ),
            (
                "arrays.nested_arrays_of_ints.0001.0000".to_string(),
                "3".to_string(),
            ),
            (
                "arrays.nested_arrays_of_ints.0001.0001".to_string(),
                "4".to_string(),
            ),
            (
                "arrays.nested_arrays_of_ints.0001.0002".to_string(),
                "5".to_string(),
            ),
            (
                "arrays.nested_mixed_array.0000.0000".to_string(),
                "1".to_string(),
            ),
            (
                "arrays.nested_mixed_array.0000.0001".to_string(),
                "2".to_string(),
            ),
            (
                "arrays.nested_mixed_array.0001.0000".to_string(),
                "a".to_string(),
            ),
            (
                "arrays.nested_mixed_array.0001.0001".to_string(),
                "b".to_string(),
            ),
            (
                "arrays.nested_mixed_array.0001.0002".to_string(),
                "c".to_string(),
            ),
            ("arrays.numbers.0000".to_string(), "0.1".to_string()),
            ("arrays.numbers.0001".to_string(), "0.2".to_string()),
            ("arrays.numbers.0002".to_string(), "0.5".to_string()),
            ("arrays.numbers.0003".to_string(), "1".to_string()),
            ("arrays.numbers.0004".to_string(), "2".to_string()),
            ("arrays.numbers.0005".to_string(), "5".to_string()),
            ("arrays.string_array.0000".to_string(), "all".to_string()),
            (
                "arrays.string_array.0001".to_string(),
                "strings".to_string(),
            ),
            (
                "arrays.string_array.0002".to_string(),
                "are the same".to_string(),
            ),
            ("arrays.string_array.0003".to_string(), "type".to_string()),
            ("database.data.0000.0000".to_string(), "delta".to_string()),
            ("database.data.0000.0001".to_string(), "phi".to_string()),
            ("database.data.0001.0000".to_string(), "3.14".to_string()),
            ("database.enabled".to_string(), "true".to_string()),
            ("database.ports.0000".to_string(), "8000".to_string()),
            ("database.ports.0001".to_string(), "8001".to_string()),
            ("database.ports.0002".to_string(), "8002".to_string()),
            ("database.temp_targets.case".to_string(), "72.0".to_string()),
            ("database.temp_targets.cpu".to_string(), "79.5".to_string()),
            ("products.0000.name".to_string(), "Hammer".to_string()),
            ("products.0000.sku".to_string(), "738594937".to_string()),
            ("products.0002.color".to_string(), "gray".to_string()),
            ("products.0002.name".to_string(), "Nail".to_string()),
            ("products.0002.sku".to_string(), "284758393".to_string()),
            ("servers.127.0.0.1".to_string(), "value".to_string()),
            ("servers.alpha.ip".to_string(), "10.0.0.1".to_string()),
            ("servers.alpha.role".to_string(), "frontend".to_string()),
            ("servers.beta.ip".to_string(), "10.0.0.2".to_string()),
            ("servers.beta.role".to_string(), "backend".to_string()),
            (
                "servers.character encoding".to_string(),
                "value".to_string(),
            ),
            (
                "strings.my \"string\" test.lines".to_string(),
                concat!(
                    "The first newline is\ntrimmed in raw strings.\n",
                    "All other whitespace\nis preserved.\n"
                )
                .to_string(),
            ),
            (
                "strings.my \"string\" test.str1".to_string(),
                "I'm a string.".to_string(),
            ),
            (
                "strings.my \"string\" test.str2".to_string(),
                "You can \"quote\" me.".to_string(),
            ),
            (
                "strings.my \"string\" test.str3".to_string(),
                "Name\tTabs\nNew Line.".to_string(),
            ),
            ("env.var1".to_string(), "utils".to_string()),
            ("env.var2".to_string(), "utils".to_string()),
        ]);

        if config.keys != expected {
            for (key, value) in &config.keys {
                if let Some(expected_value) = expected.get(key) {
                    if value != expected_value {
                        panic!(
                            "Expected value {:?} for key {:?} but found {:?}.",
                            expected_value, key, value
                        );
                    }
                } else {
                    panic!(
                        "Unexpected key {:?} found in config with value {:?}.",
                        key, value
                    );
                }
            }

            for (key, value) in &expected {
                if let Some(config_value) = config.keys.get(key) {
                    if value != config_value {
                        panic!(
                            "Expected value {:?} for key {:?} but found {:?}.",
                            value, key, config_value
                        );
                    }
                } else {
                    panic!(
                        "Expected key {:?} not found in config with value {:?}.",
                        key, value
                    );
                }
            }
        }
    }
}
