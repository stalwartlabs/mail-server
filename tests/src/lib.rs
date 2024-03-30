/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::path::PathBuf;

#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(test)]
pub mod directory;
#[cfg(test)]
pub mod imap;
#[cfg(test)]
pub mod jmap;
#[cfg(test)]
pub mod smtp;
#[cfg(test)]
pub mod store;

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
