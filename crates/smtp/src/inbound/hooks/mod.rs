/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod client;
pub mod message;

use ahash::AHashMap;
use compact_str::CompactString;
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
    pub login: CompactString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<CompactString>,
}

#[derive(Serialize, Deserialize)]
pub struct Client {
    pub ip: CompactString,
    pub port: u16,
    pub ptr: Option<CompactString>,
    pub helo: Option<CompactString>,
    #[serde(rename = "activeConnections")]
    pub active_connections: u32,
}

#[derive(Serialize, Deserialize)]
pub struct Tls {
    pub version: CompactString,
    pub cipher: CompactString,
    #[serde(rename = "cipherBits")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u16>,
    #[serde(rename = "certIssuer")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<CompactString>,
    #[serde(rename = "certSubject")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<CompactString>,
}

#[derive(Serialize, Deserialize)]
pub struct Server {
    pub name: Option<CompactString>,
    pub port: u16,
    pub ip: Option<CompactString>,
}

#[derive(Serialize, Deserialize)]
pub struct Queue {
    pub id: CompactString,
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
    pub address: CompactString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<AHashMap<CompactString, CompactString>>,
}

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub from: Address,
    pub to: Vec<Address>,
}

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub headers: Vec<(CompactString, CompactString)>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "serverHeaders")]
    #[serde(default)]
    pub server_headers: Vec<(CompactString, CompactString)>,
    pub contents: CompactString,
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
    pub enhanced_status: Option<CompactString>,
    #[serde(default)]
    pub message: Option<CompactString>,
    #[serde(default)]
    pub disconnect: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Modification {
    #[serde(rename = "changeFrom")]
    ChangeFrom {
        value: CompactString,
        #[serde(default)]
        parameters: AHashMap<CompactString, Option<CompactString>>,
    },
    #[serde(rename = "addRecipient")]
    AddRecipient {
        value: CompactString,
        #[serde(default)]
        parameters: AHashMap<CompactString, Option<CompactString>>,
    },
    #[serde(rename = "deleteRecipient")]
    DeleteRecipient { value: CompactString },
    #[serde(rename = "replaceContents")]
    ReplaceContents { value: CompactString },
    #[serde(rename = "addHeader")]
    AddHeader {
        name: CompactString,
        value: CompactString,
    },
    #[serde(rename = "insertHeader")]
    InsertHeader {
        index: u32,
        name: CompactString,
        value: CompactString,
    },
    #[serde(rename = "changeHeader")]
    ChangeHeader {
        index: u32,
        name: CompactString,
        value: CompactString,
    },
    #[serde(rename = "deleteHeader")]
    DeleteHeader { index: u32, name: CompactString },
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
