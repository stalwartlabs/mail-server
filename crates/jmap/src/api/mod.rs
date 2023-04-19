use std::sync::Arc;

use crate::JMAP;

pub mod config;
pub mod http;
pub mod request;
pub mod session;

#[derive(Clone)]
pub struct SessionManager {
    pub inner: Arc<JMAP>,
}

impl From<JMAP> for SessionManager {
    fn from(jmap: JMAP) -> Self {
        SessionManager {
            inner: Arc::new(jmap),
        }
    }
}
