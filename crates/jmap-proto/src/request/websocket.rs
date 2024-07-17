/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, collections::HashMap};

use crate::{
    error::request::{RequestError, RequestErrorType, RequestLimitError},
    parser::{json::Parser, JsonObjectParser, Token},
    request::Call,
    response::{serialize::serialize_hex, Response, ResponseMethod},
    types::{any_id::AnyId, id::Id, state::State, type_state::DataType},
};
use utils::map::vec_map::VecMap;

use super::{Request, RequestProperty};

#[derive(Debug)]
pub struct WebSocketRequest {
    pub id: Option<String>,
    pub request: Request,
}

#[derive(Debug, serde::Serialize)]
pub struct WebSocketResponse {
    #[serde(rename = "@type")]
    _type: WebSocketResponseType,

    #[serde(rename = "methodResponses")]
    method_responses: Vec<Call<ResponseMethod>>,

    #[serde(rename = "sessionState")]
    #[serde(serialize_with = "serialize_hex")]
    session_state: u32,

    #[serde(rename(deserialize = "createdIds"))]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    created_ids: HashMap<String, AnyId>,

    #[serde(rename = "requestId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub enum WebSocketResponseType {
    Response,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct WebSocketPushEnable {
    pub data_types: Vec<DataType>,
    pub push_state: Option<String>,
}

#[derive(Debug)]
pub enum WebSocketMessage {
    Request(WebSocketRequest),
    PushEnable(WebSocketPushEnable),
    PushDisable,
}

#[derive(serde::Serialize, Debug)]
pub enum WebSocketStateChangeType {
    StateChange,
}

#[derive(serde::Serialize, Debug)]
pub struct WebSocketStateChange {
    #[serde(rename = "@type")]
    pub type_: WebSocketStateChangeType,
    pub changed: VecMap<Id, VecMap<DataType, State>>,
    #[serde(rename = "pushState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    push_state: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct WebSocketRequestError {
    #[serde(rename = "@type")]
    pub type_: WebSocketRequestErrorType,

    #[serde(rename = "type")]
    p_type: RequestErrorType,

    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<RequestLimitError>,
    status: u16,
    detail: Cow<'static, str>,

    #[serde(rename = "requestId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(serde::Serialize, Debug)]
pub enum WebSocketRequestErrorType {
    RequestError,
}

enum MessageType {
    Request,
    PushEnable,
    PushDisable,
    None,
}

impl WebSocketMessage {
    pub fn parse(json: &[u8], max_calls: usize, max_size: usize) -> trc::Result<Self> {
        if json.len() <= max_size {
            let mut message_type = MessageType::None;
            let mut request = WebSocketRequest {
                id: None,
                request: Request::default(),
            };
            let mut push_enable = WebSocketPushEnable::default();

            let mut found_request_keys = false;
            let mut found_push_keys = false;

            let mut parser = Parser::new(json);
            parser.next_token::<String>()?.assert(Token::DictStart)?;
            while let Some(key) = parser.next_dict_key::<u128>()? {
                match key {
                    0x0065_7079_7440 => {
                        let rt = parser
                            .next_token::<RequestProperty>()?
                            .unwrap_string("@type")?;
                        message_type = match (rt.hash[0], rt.hash[1]) {
                            (0x0074_7365_7571_6552, 0) => MessageType::Request,
                            (0x616e_4568_7375_5074_656b_636f_5362_6557, 0x656c62) => {
                                MessageType::PushEnable
                            }
                            (0x7369_4468_7375_5074_656b_636f_5362_6557, 0x656c6261) => {
                                MessageType::PushDisable
                            }
                            _ => MessageType::None,
                        };
                    }
                    0x0073_6570_7954_6174_6164 => {
                        push_enable.data_types =
                            <Option<Vec<DataType>>>::parse(&mut parser)?.unwrap_or_default();
                        found_push_keys = true;
                    }
                    0x0065_7461_7453_6873_7570 => {
                        push_enable.push_state = parser
                            .next_token::<String>()?
                            .unwrap_string_or_null("pushState")?;
                        found_push_keys = true;
                    }
                    0x6469 => {
                        request.id = parser.next_token::<String>()?.unwrap_string_or_null("id")?;
                    }
                    _ => {
                        found_request_keys |=
                            request.request.parse_key(&mut parser, max_calls, key)?;
                    }
                }
            }

            match message_type {
                MessageType::Request if found_request_keys => {
                    Ok(WebSocketMessage::Request(request))
                }
                MessageType::PushEnable if found_push_keys => {
                    Ok(WebSocketMessage::PushEnable(push_enable))
                }
                MessageType::PushDisable if !found_request_keys && !found_push_keys => {
                    Ok(WebSocketMessage::PushDisable)
                }
                _ => Err(trc::JmapCause::NotRequest
                    .into_err()
                    .details("Invalid WebSocket JMAP request")),
            }
        } else {
            Err(trc::LimitCause::SizeRequest.into_err())
        }
    }
}

impl WebSocketRequestError {
    pub fn from_error(error: RequestError, request_id: Option<String>) -> Self {
        Self {
            type_: WebSocketRequestErrorType::RequestError,
            p_type: error.p_type,
            limit: error.limit,
            status: error.status,
            detail: error.detail,
            request_id,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl From<RequestError> for WebSocketRequestError {
    fn from(value: RequestError) -> Self {
        Self::from_error(value, None)
    }
}

impl WebSocketResponse {
    pub fn from_response(response: Response, request_id: Option<String>) -> Self {
        Self {
            _type: WebSocketResponseType::Response,
            method_responses: response.method_responses,
            session_state: response.session_state,
            created_ids: response.created_ids,
            request_id,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl WebSocketStateChange {
    pub fn new(push_state: Option<String>) -> Self {
        WebSocketStateChange {
            type_: WebSocketStateChangeType::StateChange,
            changed: VecMap::new(),
            push_state,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}
