/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use mail_parser::DateTime;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{Event, EventDetails, EventType, Key, Level, Value};
use base64::{engine::general_purpose::STANDARD, Engine};

pub struct FmtWriter<T: AsyncWrite + Unpin> {
    writer: T,
    ansi: bool,
    multiline: bool,
}

#[allow(dead_code)]
enum Color {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
}

impl<T: AsyncWrite + Unpin> FmtWriter<T> {
    pub fn new(writer: T) -> Self {
        Self {
            writer,
            ansi: false,
            multiline: false,
        }
    }

    pub fn with_ansi(self, ansi: bool) -> Self {
        Self { ansi, ..self }
    }

    pub fn with_multiline(self, multiline: bool) -> Self {
        Self { multiline, ..self }
    }

    pub async fn write(&mut self, event: &Event<EventDetails>) -> std::io::Result<()> {
        // Write timestamp
        if self.ansi {
            self.writer
                .write_all(Color::White.as_code().as_bytes())
                .await?;
        }
        self.writer
            .write_all(
                DateTime::from_timestamp(event.inner.timestamp as i64)
                    .to_rfc3339()
                    .as_bytes(),
            )
            .await?;
        if self.ansi {
            self.writer.write_all(Color::reset().as_bytes()).await?;
        }
        self.writer.write_all(" ".as_bytes()).await?;

        // Write level
        if self.ansi {
            self.writer
                .write_all(
                    match event.inner.level {
                        Level::Error => Color::Red,
                        Level::Warn => Color::Yellow,
                        Level::Info => Color::Green,
                        Level::Debug => Color::Blue,
                        Level::Trace => Color::Magenta,
                        Level::Disable => return Ok(()),
                    }
                    .as_code_bold()
                    .as_bytes(),
                )
                .await?;
        }
        self.writer
            .write_all(event.inner.level.as_str().as_bytes())
            .await?;
        if self.ansi {
            self.writer.write_all(Color::reset().as_bytes()).await?;
        }
        self.writer.write_all(" ".as_bytes()).await?;

        // Write message
        if self.ansi {
            self.writer
                .write_all(Color::White.as_code_bold().as_bytes())
                .await?;
        }
        self.writer
            .write_all(event.inner.typ.description().as_bytes())
            .await?;
        if self.ansi {
            self.writer.write_all(Color::reset().as_bytes()).await?;
        }
        self.writer.write_all(" (".as_bytes()).await?;
        self.writer
            .write_all(event.inner.typ.name().as_bytes())
            .await?;

        self.writer
            .write_all(if self.multiline { ")\n" } else { ") " }.as_bytes())
            .await?;

        // Write keys
        if let Some(parent_event) = &event.inner.span {
            self.write_keys(&parent_event.keys, &event.keys, 1).await?;
        } else {
            self.write_keys(&[], &event.keys, 1).await?;
        }

        if !self.multiline {
            self.writer.write_all("\n".as_bytes()).await?;
        }

        Ok(())
    }

    async fn write_keys(
        &mut self,
        span_keys: &[(Key, Value)],
        keys: &[(Key, Value)],
        indent: usize,
    ) -> std::io::Result<()> {
        Box::pin(async move {
            let mut is_first = true;
            for (key, value) in span_keys.iter().chain(keys.iter()) {
                if matches!(key, Key::SpanId) {
                    continue;
                } else if is_first {
                    is_first = false;
                } else if !self.multiline {
                    self.writer.write_all(", ".as_bytes()).await?;
                }

                // Write key
                if self.multiline {
                    for _ in 0..indent {
                        self.writer.write_all("\t".as_bytes()).await?;
                    }
                }
                if self.ansi {
                    self.writer
                        .write_all(Color::Cyan.as_code().as_bytes())
                        .await?;
                }
                self.writer.write_all(key.name().as_bytes()).await?;
                if self.ansi {
                    self.writer.write_all(Color::reset().as_bytes()).await?;
                }

                // Write value
                self.writer.write_all(" = ".as_bytes()).await?;
                self.write_value(value, indent).await?;

                if self.multiline && !matches!(value, Value::Event(_)) {
                    self.writer.write_all("\n".as_bytes()).await?;
                }
            }

            Ok(())
        })
        .await
    }

    async fn write_value(&mut self, value: &Value, indent: usize) -> std::io::Result<()> {
        Box::pin(async move {
            match value {
                Value::Static(v) => {
                    self.writer.write_all(v.as_bytes()).await?;
                }
                Value::String(v) => {
                    self.writer.write_all("\"".as_bytes()).await?;
                    for ch in v.as_bytes() {
                        match ch {
                            b'\r' => {
                                self.writer.write_all("\\r".as_bytes()).await?;
                            }
                            b'\n' => {
                                self.writer.write_all("\\n".as_bytes()).await?;
                            }
                            b'\t' => {
                                self.writer.write_all("\\t".as_bytes()).await?;
                            }
                            b'\\' => {
                                self.writer.write_all("\\\\".as_bytes()).await?;
                            }
                            _ => {
                                self.writer.write_all(&[*ch]).await?;
                            }
                        }
                    }
                    self.writer.write_all("\"".as_bytes()).await?;
                }
                Value::UInt(v) => {
                    self.writer.write_all(v.to_string().as_bytes()).await?;
                }
                Value::Int(v) => {
                    self.writer.write_all(v.to_string().as_bytes()).await?;
                }
                Value::Float(v) => {
                    self.writer.write_all(v.to_string().as_bytes()).await?;
                }
                Value::Timestamp(v) => {
                    self.writer
                        .write_all(DateTime::from_timestamp(*v as i64).to_rfc3339().as_bytes())
                        .await?;
                }
                Value::Duration(v) => {
                    self.writer.write_all(v.to_string().as_bytes()).await?;
                    self.writer.write_all("ms".as_bytes()).await?;
                }
                Value::Bytes(bytes) => {
                    self.writer.write_all("base64:".as_bytes()).await?;
                    self.writer
                        .write_all(STANDARD.encode(bytes).as_bytes())
                        .await?;
                }
                Value::Bool(true) => {
                    self.writer.write_all("true".as_bytes()).await?;
                }
                Value::Bool(false) => {
                    self.writer.write_all("false".as_bytes()).await?;
                }
                Value::Ipv4(v) => {
                    self.writer.write_all(v.to_string().as_bytes()).await?;
                }
                Value::Ipv6(v) => {
                    self.writer.write_all(v.to_string().as_bytes()).await?;
                }
                Value::Event(e) => {
                    self.writer
                        .write_all(e.inner.description().as_bytes())
                        .await?;
                    self.writer.write_all(" (".as_bytes()).await?;
                    self.writer.write_all(e.inner.name().as_bytes()).await?;
                    self.writer.write_all(")".as_bytes()).await?;
                    if !e.keys.is_empty() {
                        self.writer
                            .write_all(if self.multiline { "\n" } else { " { " }.as_bytes())
                            .await?;

                        self.write_keys(&e.keys, &[], indent + 1).await?;

                        if !self.multiline {
                            self.writer.write_all(" }".as_bytes()).await?;
                        }
                    } else if self.multiline {
                        self.writer.write_all("\n".as_bytes()).await?;
                    }
                }
                Value::Array(arr) => {
                    self.writer.write_all("[".as_bytes()).await?;
                    for (pos, value) in arr.iter().enumerate() {
                        if pos > 0 {
                            self.writer.write_all(", ".as_bytes()).await?;
                        }
                        self.write_value(value, indent).await?;
                    }
                    self.writer.write_all("]".as_bytes()).await?;
                }
                Value::None => {
                    self.writer.write_all("(null)".as_bytes()).await?;
                }
            }

            Ok(())
        })
        .await
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush().await
    }

    pub fn update_writer(&mut self, writer: T) {
        self.writer = writer;
    }
}

impl Color {
    pub fn as_code(&self) -> &'static str {
        match self {
            Color::Black => "\x1b[30m",
            Color::Red => "\x1b[31m",
            Color::Green => "\x1b[32m",
            Color::Yellow => "\x1b[33m",
            Color::Blue => "\x1b[34m",
            Color::Magenta => "\x1b[35m",
            Color::Cyan => "\x1b[36m",
            Color::White => "\x1b[37m",
        }
    }

    pub fn as_code_bold(&self) -> &'static str {
        match self {
            Color::Black => "\x1b[30;1m",
            Color::Red => "\x1b[31;1m",
            Color::Green => "\x1b[32;1m",
            Color::Yellow => "\x1b[33;1m",
            Color::Blue => "\x1b[34;1m",
            Color::Magenta => "\x1b[35;1m",
            Color::Cyan => "\x1b[36;1m",
            Color::White => "\x1b[37;1m",
        }
    }

    pub fn reset() -> &'static str {
        "\x1b[0m"
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Static(value) => value.fmt(f),
            Value::String(value) => value.fmt(f),
            Value::UInt(value) => value.fmt(f),
            Value::Int(value) => value.fmt(f),
            Value::Float(value) => value.fmt(f),
            Value::Timestamp(value) => value.fmt(f),
            Value::Duration(value) => value.fmt(f),
            Value::Bytes(value) => STANDARD.encode(value).fmt(f),
            Value::Bool(value) => value.fmt(f),
            Value::Ipv4(value) => value.fmt(f),
            Value::Ipv6(value) => value.fmt(f),
            Value::Event(value) => {
                "{".fmt(f)?;
                value.fmt(f)?;
                "}".fmt(f)
            }
            Value::Array(value) => {
                f.write_str("[")?;
                for (i, value) in value.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    value.fmt(f)?;
                }
                f.write_str("]")
            }
            Value::None => "(null)".fmt(f),
        }
    }
}

impl Display for Event<EventType> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.description().fmt(f)?;
        " (".fmt(f)?;
        self.inner.name().fmt(f)?;
        ")".fmt(f)?;

        if !self.keys.is_empty() {
            f.write_str(": ")?;
            for (i, (key, value)) in self.keys.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                key.name().fmt(f)?;
                f.write_str(" = ")?;
                value.fmt(f)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{EventType, Level};

    fn to_camel_case(name: &str) -> String {
        let mut out = String::with_capacity(name.len());
        let mut upper = true;
        for ch in name.chars() {
            if ch.is_alphanumeric() {
                if upper {
                    out.push(ch.to_ascii_uppercase());
                    upper = false;
                } else {
                    out.push(ch);
                }
            } else {
                upper = true;
            }
        }
        out
    }

    fn event_to_class(name: &str) -> String {
        let (group, name) = name.split_once('.').unwrap();
        let group = to_camel_case(group);
        format!(
            "EventType::{}({}Event::{})",
            group,
            group,
            to_camel_case(name)
        )
    }

    #[test]
    fn print_all_events() {
        assert!(!Level::Disable.is_contained(Level::Warn));
        assert!(Level::Trace.is_contained(Level::Error));
        assert!(Level::Trace.is_contained(Level::Debug));
        assert!(!Level::Error.is_contained(Level::Trace));
        assert!(!Level::Debug.is_contained(Level::Trace));

        let mut names = Vec::with_capacity(100);

        for event in EventType::variants() {
            names.push((event.name(), event.description(), event.level().as_str()));
            assert_eq!(EventType::try_parse(event.name()).unwrap(), event);
        }

        // sort by name
        names.sort_by(|a, b| a.0.cmp(b.0));

        /*for (name, description, level) in names {
            //println!("{:?},", name);
            println!("|`{name}`|{description}|`{level}`|")
        }*/

        for (pos, (name, _, _)) in names.iter().enumerate() {
            //println!("{:?},", name);
            //println!("{} => Some({}),", pos, event_to_class(name));
            println!("{} => {},", event_to_class(name), pos);
        }
    }
}
