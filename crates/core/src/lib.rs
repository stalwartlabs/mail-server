use store::{fts::Language, Store};

pub mod api;
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
