use jmap_proto::error::method::MethodError;
use store::{fts::Language, Store};

pub mod api;
pub mod blob;
pub mod email;

pub struct JMAP {
    pub store: Store,
    pub config: Config,
}

pub struct Config {
    pub default_language: Language,
    pub query_max_results: usize,
    pub request_max_size: usize,
    pub request_max_calls: usize,
    pub upload_max_size: usize,
}

pub enum MaybeError {
    Temporary(String),
    Permanent(String),
}

impl From<store::Error> for MaybeError {
    fn from(e: store::Error) -> Self {
        match e {
            store::Error::InternalError(msg) => {
                let log = "true";
                MaybeError::Temporary(format!("Database error: {msg}"))
            }
            store::Error::AssertValueFailed => {
                MaybeError::Permanent("Assert value failed".to_string())
            }
        }
    }
}

impl From<MaybeError> for MethodError {
    fn from(value: MaybeError) -> Self {
        match value {
            MaybeError::Temporary(msg) => {
                let log = "true";
                MethodError::ServerPartialFail
            }
            MaybeError::Permanent(msg) => MethodError::InvalidArguments(msg),
        }
    }
}
