use std::sync::Arc;

use crate::JMAP;

pub mod http;
pub mod request;
pub mod session;

#[derive(Clone)]
pub struct SessionManager {
    pub inner: Arc<JMAP>,
}
