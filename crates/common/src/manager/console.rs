/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::env;
use std::io::{self, Write};

use base64::Engine;
use base64::engine::general_purpose;
use store::write::{AnyClass, AnyKey, BatchBuilder, ValueClass};
use store::{
    Deserialize, IterateParams, SUBSPACE_BITMAP_ID, SUBSPACE_BITMAP_TAG, SUBSPACE_BITMAP_TEXT,
    SUBSPACE_INDEXES, Store,
};

const HELP: &str = concat!(
    "Stalwart Server v",
    env!("CARGO_PKG_VERSION"),
    r#" Data Store CLI

Enter commands (type 'help' for available commands).
"#
);

pub async fn store_console(store: Store) {
    print!("{HELP}");

    if matches!(store, Store::None) {
        println!("No store available. Verify your configuration.");
        return;
    }

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "scan" => {
                if parts.len() != 3 {
                    println!("Usage: scan <from_key> <to_key>");
                } else if let (Some(from_key), Some(to_key)) =
                    (parse_key(parts[1]), parse_key(parts[2]))
                {
                    println!("Scanning from {:?} to {:?}", from_key, to_key);
                    let mut from_key = from_key.into_iter();
                    let mut to_key = to_key.into_iter();
                    let from_subspace = from_key.next().unwrap();
                    let to_subspace = to_key.next().unwrap();

                    if from_subspace != to_subspace {
                        println!("Keys must be in the same subspace.");
                        return;
                    }

                    store
                        .iterate(
                            IterateParams::new(
                                AnyKey {
                                    subspace: from_subspace,
                                    key: from_key.collect::<Vec<_>>(),
                                },
                                AnyKey {
                                    subspace: to_subspace,
                                    key: to_key.collect::<Vec<_>>(),
                                },
                            )
                            .set_values(
                                ![
                                    SUBSPACE_INDEXES,
                                    SUBSPACE_BITMAP_ID,
                                    SUBSPACE_BITMAP_TAG,
                                    SUBSPACE_BITMAP_TEXT,
                                ]
                                .contains(&from_subspace),
                            ),
                            |key, value| {
                                print!("{}", char::from(from_subspace));
                                print_escaped(key);
                                print!(" : ");
                                print_escaped(value);
                                println!();
                                Ok(true)
                            },
                        )
                        .await
                        .expect("Failed to scan keys");
                }
            }
            "delete" => match (parts.get(1), parts.get(2)) {
                (Some(from_key), Some(to_key)) => {
                    if let (Some(from_key), Some(to_key)) = (parse_key(from_key), parse_key(to_key))
                    {
                        let mut from_key = from_key.into_iter();
                        let mut to_key = to_key.into_iter();

                        let from_key = AnyKey {
                            subspace: from_key.next().unwrap(),
                            key: from_key.collect::<Vec<_>>(),
                        };
                        let to_key = AnyKey {
                            subspace: to_key.next().unwrap(),
                            key: to_key.collect::<Vec<_>>(),
                        };

                        if from_key.subspace != to_key.subspace {
                            println!("Keys must be in the same subspace.");
                            return;
                        }

                        let mut total = 0;
                        store
                            .iterate(
                                IterateParams::new(from_key.clone(), to_key.clone()).no_values(),
                                |_, _| {
                                    total += 1;
                                    Ok(true)
                                },
                            )
                            .await
                            .expect("Failed to scan keys");

                        if total > 0 {
                            print!("Are you sure you want to delete {total} keys? (y/N): ");
                            io::stdout().flush().unwrap();
                            let mut response = String::new();
                            io::stdin().read_line(&mut response).unwrap();
                            if !response.trim().eq_ignore_ascii_case("y") {
                                println!("Aborted.");
                                return;
                            }

                            store
                                .delete_range(from_key, to_key)
                                .await
                                .expect("Failed to delete keys");
                            println!("Deleted {total} keys.");
                        } else {
                            println!("No keys found.");
                        }
                    }
                }
                (Some(key), None) => {
                    if let Some(key) = parse_key(key) {
                        println!("Deleting key: {:?}", key);
                        let mut key = key.into_iter();
                        let mut batch = BatchBuilder::new();
                        batch.clear(ValueClass::Any(AnyClass {
                            subspace: key.next().unwrap(),
                            key: key.collect(),
                        }));
                        if let Err(err) = store.write(batch.build_all()).await {
                            println!("Failed to delete key: {}", err);
                        }
                    }
                }
                _ => {
                    println!("Usage: delete <from_key> [<to_key>]");
                }
            },
            "get" => {
                if parts.len() != 2 {
                    println!("Usage: get <key>");
                } else if let Some(key) = parse_key(parts[1]) {
                    let mut key = key.into_iter();
                    match store
                        .get_value::<RawValue>(AnyKey {
                            subspace: key.next().unwrap(),
                            key: key.collect::<Vec<_>>(),
                        })
                        .await
                    {
                        Ok(Some(data)) => {
                            print_escaped(&data.0);
                            println!();
                        }
                        Ok(None) => {
                            println!("Key not found.");
                        }
                        Err(err) => {
                            println!("Failed to retrieve key: {}", err);
                        }
                    }
                }
            }
            "put" => {
                if parts.len() < 2 {
                    println!("Usage: put <key> [<value>]");
                } else if let Some(key) = parse_key(parts[1]) {
                    let value = parts.get(2).map(|v| parse_value(v)).unwrap_or_default();
                    println!("Putting key: {key:?}");

                    let mut key = key.into_iter();
                    let mut batch = BatchBuilder::new();
                    batch.set(
                        ValueClass::Any(AnyClass {
                            subspace: key.next().unwrap(),
                            key: key.collect(),
                        }),
                        value,
                    );
                    if let Err(err) = store.write(batch.build_all()).await {
                        println!("Failed to insert key: {}", err);
                    }
                }
            }
            "help" => {
                print_help();
            }
            "exit" | "quit" => {
                println!("Exiting...");
                break;
            }
            _ => {
                println!("Unknown command. Type 'help' for available commands.");
            }
        }
    }
}

fn parse_key(input: &str) -> Option<Vec<u8>> {
    let result = if let Some(key) = input.strip_prefix("base64:") {
        base64_decode(key)
    } else {
        parse_binary(input)
    };
    if matches!(result.first(), Some(ch) if ch.is_ascii_alphabetic() && ch.is_ascii_lowercase()) {
        Some(result)
    } else {
        println!("Invalid key: {result:?}");
        None
    }
}

fn parse_value(input: &str) -> Vec<u8> {
    if let Some(key) = input.strip_prefix("base64:") {
        base64_decode(key)
    } else {
        parse_binary(input)
    }
}

fn base64_decode(input: &str) -> Vec<u8> {
    general_purpose::STANDARD
        .decode(input)
        .expect("Failed to decode base64")
}

fn parse_binary(input: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    if hex.len() == 2 {
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte);
                        } else {
                            result.extend_from_slice(b"\\x");
                            result.extend_from_slice(hex.as_bytes());
                        }
                    } else {
                        result.push(b'\\');
                        result.push(b'x');
                        result.extend_from_slice(hex.as_bytes());
                    }
                }
                Some(other) => {
                    result.push(b'\\');
                    result.push(other as u8);
                }
                None => {
                    result.push(b'\\');
                }
            }
        } else {
            result.push(c as u8);
        }
    }

    result
}

fn print_escaped(bytes: &[u8]) {
    for ch in bytes {
        if ch.is_ascii() && !ch.is_ascii_control() && *ch != b'\\' {
            print!("{}", *ch as char);
        } else {
            print!("\\x{:02x}", ch);
        }
    }
}

fn print_help() {
    println!("Available commands:");
    println!("  scan <from_key> <to_key>");
    println!("  delete <from_key> [<to_key>]");
    println!("  get <key>");
    println!("  put <key> [<value>]");
    println!("  help");
    println!("  exit/quit");
    println!("Note: Keys and values can be prefixed with 'base64:' for base64 encoding");
    println!("      or use escaped hex values (e.g., \\x41 for 'A')");
}

struct RawValue(Vec<u8>);

impl Deserialize for RawValue {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(RawValue(bytes.to_vec()))
    }
}
