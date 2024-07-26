/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use hyper::StatusCode;
use jmap_proto::types::{id::Id, state::State, type_state::DataType};
use serde::Serialize;
use utils::map::vec_map::VecMap;

use crate::JmapInstance;

pub mod autoconfig;
pub mod event_source;
pub mod http;
pub mod management;
pub mod request;
pub mod session;

#[derive(Clone)]
pub struct JmapSessionManager {
    pub inner: JmapInstance,
}

impl JmapSessionManager {
    pub fn new(inner: JmapInstance) -> Self {
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

pub enum HttpResponseBody {
    Text(String),
    Binary(Vec<u8>),
    Stream(http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>),
    WebsocketUpgrade(String),
    Empty,
}

pub struct HttpResponse {
    pub status: StatusCode,
    pub content_type: Cow<'static, str>,
    pub content_disposition: Cow<'static, str>,
    pub cache_control: Cow<'static, str>,
    pub body: HttpResponseBody,
}

pub type HttpRequest = hyper::Request<hyper::body::Incoming>;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum StateChangeType {
    StateChange,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct StateChangeResponse {
    #[serde(rename = "@type")]
    pub type_: StateChangeType,
    pub changed: VecMap<Id, VecMap<DataType, State>>,
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
