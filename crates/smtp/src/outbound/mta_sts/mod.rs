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

pub mod lookup;
pub mod parse;
pub mod verify;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum MxPattern {
    Equals(String),
    StartsWith(String),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    pub mx: Vec<MxPattern>,
    pub max_age: u64,
}

#[derive(Debug)]
pub enum Error {
    Dns(mail_auth::Error),
    Http(reqwest::Error),
    InvalidPolicy(String),
}
