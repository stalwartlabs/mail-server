use std::sync::Arc;

use hyper::StatusCode;
use jmap_proto::types::{id::Id, state::State, type_state::TypeState};
use serde::Serialize;
use utils::map::vec_map::VecMap;

use crate::JMAP;

pub mod config;
pub mod event_source;
pub mod http;
pub mod request;
pub mod session;

#[derive(Clone)]
pub struct JmapSessionManager {
    pub inner: Arc<JMAP>,
}

impl JmapSessionManager {
    pub fn new(inner: Arc<JMAP>) -> Self {
        Self { inner }
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

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum StateChangeType {
    StateChange,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct StateChangeResponse {
    #[serde(rename = "@type")]
    pub type_: StateChangeType,
    pub changed: VecMap<Id, VecMap<TypeState, State>>,
}

impl StateChangeResponse {
    pub fn new() -> Self {
        Self {
            type_: StateChangeType::StateChange,
            changed: VecMap::new(),
        }
    }
}

impl Default for StateChangeResponse {
    fn default() -> Self {
        Self::new()
    }
}
