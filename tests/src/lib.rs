/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::path::PathBuf;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
#[cfg(test)]
use trc::Collector;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(test)]
pub mod cluster;
#[cfg(test)]
pub mod directory;
#[cfg(test)]
pub mod http_server;
#[cfg(test)]
pub mod imap;
#[cfg(test)]
pub mod jmap;
#[cfg(test)]
pub mod smtp;
#[cfg(test)]
pub mod store;
#[cfg(test)]
pub mod webdav;

pub fn add_test_certs(config: &str) -> String {
    let mut cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cert_path.push("resources");
    let mut cert = cert_path.clone();
    cert.push("tls_cert.pem");
    let mut pk = cert_path.clone();
    pk.push("tls_privatekey.pem");

    config
        .replace("{CERT}", cert.as_path().to_str().unwrap())
        .replace("{PK}", pk.as_path().to_str().unwrap())
}

#[cfg(test)]
pub trait AssertConfig {
    fn assert_no_errors(self) -> Self;
    fn assert_no_warnings(self) -> Self;
}

#[cfg(test)]
impl AssertConfig for utils::config::Config {
    fn assert_no_errors(self) -> Self {
        if !self.errors.is_empty() {
            panic!("Errors: {:#?}", self.errors);
        }
        self
    }

    fn assert_no_warnings(self) -> Self {
        if !self.warnings.is_empty() {
            panic!("Warnings: {:#?}", self.warnings);
        }
        self
    }
}

#[cfg(test)]
pub fn enable_logging() {
    use common::config::telemetry::Telemetry;

    if let Ok(level) = std::env::var("LOG") {
        if !Collector::is_enabled() {
            Telemetry::test_tracer(level.parse().expect("Invalid log level"));
        }
    }
}

pub const TEST_USERS: &[(&str, &str, &str, &str)] = &[
    ("admin", "secret1", "Superuser", "admin@example,com"),
    ("john", "secret2", "John Doe", "jdoe@example.com"),
    (
        "jane",
        "secret3",
        "Jane Doe-Smith",
        "jane.smith@example.com",
    ),
    ("bill", "secret4", "Bill Foobar", "bill@example,com"),
    ("mike", "secret5", "Mike Noquota", "mike@example,com"),
];
