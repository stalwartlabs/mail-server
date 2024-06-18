use ahash::AHashMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Request {
    context: Context,
    #[serde(skip_serializing_if = "Option::is_none")]
    envelope: Option<Envelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<Message>,
}

#[derive(Serialize, Deserialize)]
pub struct Context {
    stage: Stage,
    client: Client,
    #[serde(skip_serializing_if = "Option::is_none")]
    sasl: Option<Sasl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<Tls>,
    server: Server,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue: Option<Queue>,
    protocol: Protocol,
}

#[derive(Serialize, Deserialize)]
pub struct Sasl {
    login: String,
    method: String,
}

#[derive(Serialize, Deserialize)]
pub struct Client {
    ip: String,
    port: u16,
    ptr: Option<String>,
    helo: Option<String>,
    #[serde(rename = "activeConnections")]
    active_connections: u32,
}

#[derive(Serialize, Deserialize)]
pub struct Tls {
    version: String,
    cipher: String,
    #[serde(rename = "cipherBits")]
    #[serde(skip_serializing_if = "Option::is_none")]
    bits: Option<u16>,
    #[serde(rename = "certIssuer")]
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(rename = "certSubject")]
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Server {
    name: Option<String>,
    port: u16,
    ip: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Queue {
    id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Protocol {
    version: String,
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
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<AHashMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    from: Address,
    to: Vec<Address>,
}

#[derive(Serialize, Deserialize)]
pub struct Message {
    headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "serverHeaders")]
    server_headers: Vec<(String, String)>,
    body: String,
    size: usize,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    action: Action,
    modifications: Vec<Modification>,
}

#[derive(Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "accept")]
    Accept,
    #[serde(rename = "discard")]
    Discard,
    #[serde(rename = "reject")]
    Reject,
    #[serde(rename = "tempFail")]
    Tempfail,
    #[serde(rename = "shutdown")]
    Shutdown,
    #[serde(rename = "connectionFailure")]
    ConnectionFailure,
    #[serde(rename = "replyCode")]
    ReplyCode,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Modification {
    #[serde(rename = "changeFrom")]
    ChangeFrom {
        value: String,
        #[serde(default)]
        parameters: AHashMap<String, String>,
    },
    #[serde(rename = "addRecipient")]
    AddRecipient {
        value: String,
        #[serde(default)]
        parameters: AHashMap<String, String>,
    },
    #[serde(rename = "deleteRecipient")]
    DeleteRecipient { value: String },
    #[serde(rename = "replaceBody")]
    ReplaceBody { value: String },
    #[serde(rename = "addHeader")]
    AddHeader { name: String, value: String },
    #[serde(rename = "insertHeader")]
    InsertHeader {
        index: i32,
        name: String,
        value: String,
    },
    #[serde(rename = "changeHeader")]
    ChangeHeader {
        index: i32,
        name: String,
        value: String,
    },
    #[serde(rename = "deleteHeader")]
    DeleteHeader {
        #[serde(default)]
        index: Option<i32>,
        name: String,
    },
    #[serde(rename = "quarantine")]
    Quarantine { value: String },
}
