use std::sync::Arc;

use hyper::StatusCode;
use serde::Serialize;

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

pub struct JsonResponse<T: Serialize> {
    status: StatusCode,
    inner: T,
}

pub struct HtmlResponse {
    status: StatusCode,
    body: String,
}

pub type HttpRequest = hyper::Request<hyper::body::Incoming>;
pub type HttpResponse =
    hyper::Response<http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>>;
