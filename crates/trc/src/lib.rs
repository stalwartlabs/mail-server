/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod conv;
pub mod imple;
pub mod macros;

use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub type Result<T> = std::result::Result<T, Error>;
pub type Error = Context<Cause, ERROR_CONTEXT_SIZE>;
pub type Trace = Context<Event, TRACE_CONTEXT_SIZE>;

const ERROR_CONTEXT_SIZE: usize = 5;
const TRACE_CONTEXT_SIZE: usize = 10;

#[derive(Debug, Default, Clone)]
pub enum Value {
    Static(&'static str),
    String(String),
    UInt(u64),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Bool(bool),
    Ipv4(Ipv4Addr),
    Ipv6(Box<Ipv6Addr>),
    Protocol(Protocol),
    Error(Box<Error>),
    ErrorKind(ErrorKind),
    Array(Vec<Value>),
    #[default]
    None,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    RemoteIp,
    #[default]
    CausedBy,
    Reason,
    Details,
    Query,
    Result,
    Parameters,
    Type,
    Id,
    Code,
    Key,
    Value,
    Size,
    Status,
    Total,
    Protocol,
    Property,
    Path,
    Url,
    DocumentId,
    Collection,
    AccountId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    NewConnection,
    Error(Cause),
    SqlQuery,
    LdapQuery,
    PurgeTaskStarted,
    PurgeTaskRunning,
    PurgeTaskFinished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    FoundationDB,
    MySQL,
    PostgreSQL,
    RocksDB,
    SQLite,
    ElasticSearch,
    Redis,
    S3,
    Io,
    Imap,
    Smtp,
    Ldap,
    BlobMissingMarker,
    Unknown,
    Purge,
    AssertValue,
    Timeout,
    Thread,
    Pool,
    DataCorruption,
    Decompress,
    Deserialize,
    NotConfigured,
    Unsupported,
    Unexpected,
    MissingParameter,
    Invalid,
    AlreadyExists,
    NotFound,
    Configuration,
    Fetch,
    Acme,
    Http,
    Crypto,
    Dns,
    Authentication,
    MissingTotp,
    Jmap,
    OverQuota,
    OverBlobQuota, //RequestError::over_blob_quota
    Ingest,
    Network,
    TooManyRequests, //RequestError::too_many_requests() + disconnect imap StatusResponse::bye("Too many authentication requests from this IP address.")
    TooManyConcurrentRequests, //RequestError::limit(RequestLimitError::ConcurrentRequest) StatusResponse::bye("Too many concurrent IMAP connections.").into_bytes(),
    TooManyConcurrentUploads,  //RequestError::limit(RequestLimitError::ConcurrentUpload)
    TooManyAuthAttempts,       //RequestError::too_many_auth_attempts() + disconnect imap
    Banned,
}

/*

RequestError::unauthorized().into_http_response()

RequestError::blank(
                                    403,
                                    "TOTP code required",
                                    concat!(
                                        "A TOTP code is required to authenticate this account. ",
                                        "Try authenticating again using 'secret$totp_token'."
                                    ),
                                )

*/

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Jmap,
    Imap,
    Smtp,
    ManageSieve,
    Ldap,
    Sql,
}

#[derive(Debug, Clone)]
pub struct Context<T, const N: usize> {
    inner: T,
    keys: [(Key, Value); N],
    keys_size: usize,
}

pub trait AddContext<T> {
    fn caused_by(self, location: &'static str) -> Result<T>;
    fn add_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce(Error) -> Error;
}
