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

pub mod client;
pub mod message;

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub context: Context,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

#[derive(Serialize, Deserialize)]
pub struct Context {
    pub stage: Stage,
    pub client: Client,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sasl: Option<Sasl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    pub server: Server,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<Queue>,
    pub protocol: Protocol,
}

#[derive(Serialize, Deserialize)]
pub struct Sasl {
    pub login: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Client {
    pub ip: String,
    pub port: u16,
    pub ptr: Option<String>,
    pub helo: Option<String>,
    #[serde(rename = "activeConnections")]
    pub active_connections: u32,
}

#[derive(Serialize, Deserialize)]
pub struct Tls {
    pub version: String,
    pub cipher: String,
    #[serde(rename = "cipherBits")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u16>,
    #[serde(rename = "certIssuer")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(rename = "certSubject")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Server {
    pub name: Option<String>,
    pub port: u16,
    pub ip: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Queue {
    pub id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Protocol {
    pub version: u32,
}

#[derive(Serialize, Deserialize)]
pub enum Stage {
    #[serde(rename = "connect")]
    Connect,
    #[serde(rename = "ehlo")]
    Ehlo,
    #[serde(rename = "auth")]
    Auth,
    #[serde(rename = "mail")]
    Mail,
    #[serde(rename = "rcpt")]
    Rcpt,
    #[serde(rename = "data")]
    Data,
}

#[derive(Serialize, Deserialize)]
pub struct Address {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<AHashMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub from: Address,
    pub to: Vec<Address>,
}

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "serverHeaders")]
    #[serde(default)]
    pub server_headers: Vec<(String, String)>,
    pub contents: String,
    pub size: usize,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub action: Action,
    #[serde(default)]
    pub response: Option<SmtpResponse>,
    #[serde(default)]
    pub modifications: Vec<Modification>,
}

#[derive(Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "accept")]
    Accept,
    #[serde(rename = "discard")]
    Discard,
    #[serde(rename = "reject")]
    Reject,
    #[serde(rename = "quarantine")]
    Quarantine,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SmtpResponse {
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub enhanced_status: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub disconnect: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Modification {
    #[serde(rename = "changeFrom")]
    ChangeFrom {
        value: String,
        #[serde(default)]
        parameters: AHashMap<String, Option<String>>,
    },
    #[serde(rename = "addRecipient")]
    AddRecipient {
        value: String,
        #[serde(default)]
        parameters: AHashMap<String, Option<String>>,
    },
    #[serde(rename = "deleteRecipient")]
    DeleteRecipient { value: String },
    #[serde(rename = "replaceContents")]
    ReplaceContents { value: String },
    #[serde(rename = "addHeader")]
    AddHeader { name: String, value: String },
    #[serde(rename = "insertHeader")]
    InsertHeader {
        index: u32,
        name: String,
        value: String,
    },
    #[serde(rename = "changeHeader")]
    ChangeHeader {
        index: u32,
        name: String,
        value: String,
    },
    #[serde(rename = "deleteHeader")]
    DeleteHeader { index: u32, name: String },
}

impl From<common::config::smtp::session::Stage> for Stage {
    fn from(value: common::config::smtp::session::Stage) -> Self {
        match value {
            common::config::smtp::session::Stage::Connect => Stage::Connect,
            common::config::smtp::session::Stage::Ehlo => Stage::Ehlo,
            common::config::smtp::session::Stage::Auth => Stage::Auth,
            common::config::smtp::session::Stage::Mail => Stage::Mail,
            common::config::smtp::session::Stage::Rcpt => Stage::Rcpt,
            common::config::smtp::session::Stage::Data => Stage::Data,
        }
    }
}
