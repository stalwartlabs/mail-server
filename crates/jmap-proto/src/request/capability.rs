/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use utils::map::vec_map::VecMap;

use crate::{
    error::request::RequestError,
    parser::{json::Parser, Error, JsonObjectParser},
    types::type_state::DataType,
};

#[derive(Debug, Clone, Copy, serde::Serialize, Hash, PartialEq, Eq)]
pub enum Capability {
    #[serde(rename(serialize = "urn:ietf:params:jmap:core"))]
    Core = 1 << 0,
    #[serde(rename(serialize = "urn:ietf:params:jmap:mail"))]
    Mail = 1 << 1,
    #[serde(rename(serialize = "urn:ietf:params:jmap:submission"))]
    Submission = 1 << 2,
    #[serde(rename(serialize = "urn:ietf:params:jmap:vacationresponse"))]
    VacationResponse = 1 << 3,
    #[serde(rename(serialize = "urn:ietf:params:jmap:contacts"))]
    Contacts = 1 << 4,
    #[serde(rename(serialize = "urn:ietf:params:jmap:calendars"))]
    Calendars = 1 << 5,
    #[serde(rename(serialize = "urn:ietf:params:jmap:websocket"))]
    WebSocket = 1 << 6,
    #[serde(rename(serialize = "urn:ietf:params:jmap:sieve"))]
    Sieve = 1 << 7,
    #[serde(rename(serialize = "urn:ietf:params:jmap:blob"))]
    Blob = 1 << 8,
    #[serde(rename(serialize = "urn:ietf:params:jmap:quota"))]
    Quota = 1 << 9,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum Capabilities {
    Core(CoreCapabilities),
    Mail(MailCapabilities),
    Submission(SubmissionCapabilities),
    WebSocket(WebSocketCapabilities),
    SieveAccount(SieveAccountCapabilities),
    SieveSession(SieveSessionCapabilities),
    Blob(BlobCapabilities),
    Empty(EmptyCapabilities),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoreCapabilities {
    #[serde(rename(serialize = "maxSizeUpload"))]
    pub max_size_upload: usize,
    #[serde(rename(serialize = "maxConcurrentUpload"))]
    pub max_concurrent_upload: usize,
    #[serde(rename(serialize = "maxSizeRequest"))]
    pub max_size_request: usize,
    #[serde(rename(serialize = "maxConcurrentRequests"))]
    pub max_concurrent_requests: usize,
    #[serde(rename(serialize = "maxCallsInRequest"))]
    pub max_calls_in_request: usize,
    #[serde(rename(serialize = "maxObjectsInGet"))]
    pub max_objects_in_get: usize,
    #[serde(rename(serialize = "maxObjectsInSet"))]
    pub max_objects_in_set: usize,
    #[serde(rename(serialize = "collationAlgorithms"))]
    pub collation_algorithms: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WebSocketCapabilities {
    #[serde(rename(serialize = "url"))]
    pub url: String,
    #[serde(rename(serialize = "supportsPush"))]
    pub supports_push: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SieveSessionCapabilities {
    #[serde(rename(serialize = "implementation"))]
    pub implementation: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SieveAccountCapabilities {
    #[serde(rename(serialize = "maxSizeScriptName"))]
    pub max_script_name: usize,
    #[serde(rename(serialize = "maxSizeScript"))]
    pub max_script_size: usize,
    #[serde(rename(serialize = "maxNumberScripts"))]
    pub max_scripts: usize,
    #[serde(rename(serialize = "maxNumberRedirects"))]
    pub max_redirects: usize,
    #[serde(rename(serialize = "sieveExtensions"))]
    pub extensions: Vec<String>,
    #[serde(rename(serialize = "notificationMethods"))]
    pub notification_methods: Option<Vec<String>>,
    #[serde(rename(serialize = "externalLists"))]
    pub ext_lists: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MailCapabilities {
    #[serde(rename(serialize = "maxMailboxesPerEmail"))]
    pub max_mailboxes_per_email: Option<usize>,
    #[serde(rename(serialize = "maxMailboxDepth"))]
    pub max_mailbox_depth: usize,
    #[serde(rename(serialize = "maxSizeMailboxName"))]
    pub max_size_mailbox_name: usize,
    #[serde(rename(serialize = "maxSizeAttachmentsPerEmail"))]
    pub max_size_attachments_per_email: usize,
    #[serde(rename(serialize = "emailQuerySortOptions"))]
    pub email_query_sort_options: Vec<String>,
    #[serde(rename(serialize = "mayCreateTopLevelMailbox"))]
    pub may_create_top_level_mailbox: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SubmissionCapabilities {
    #[serde(rename(serialize = "maxDelayedSend"))]
    pub max_delayed_send: usize,
    #[serde(rename(serialize = "submissionExtensions"))]
    pub submission_extensions: VecMap<String, Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlobCapabilities {
    #[serde(rename(serialize = "maxSizeBlobSet"))]
    pub max_size_blob_set: usize,
    #[serde(rename(serialize = "maxDataSources"))]
    pub max_data_sources: usize,
    #[serde(rename(serialize = "supportedTypeNames"))]
    pub supported_type_names: Vec<DataType>,
    #[serde(rename(serialize = "supportedDigestAlgorithms"))]
    pub supported_digest_algorithms: Vec<&'static str>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct EmptyCapabilities {}

impl Default for SieveSessionCapabilities {
    fn default() -> Self {
        Self {
            implementation: concat!("Stalwart JMAP v", env!("CARGO_PKG_VERSION"),),
        }
    }
}

impl JsonObjectParser for Capability {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        for ch in b"urn:ietf:params:jmap:" {
            if parser
                .next_unescaped()?
                .ok_or_else(|| parser.error_capability())?
                != *ch
            {
                return Err(parser.error_capability());
            }
        }

        match u128::parse(parser) {
            Ok(key) => match key {
                0x6572_6f63 => Ok(Capability::Core),
                0x6c69_616d => Ok(Capability::Mail),
                0x6e6f_6973_7369_6d62_7573 => Ok(Capability::Submission),
                0x6573_6e6f_7073_6572_6e6f_6974_6163_6176 => Ok(Capability::VacationResponse),
                0x7374_6361_746e_6f63 => Ok(Capability::Contacts),
                0x0073_7261_646e_656c_6163 => Ok(Capability::Calendars),
                0x0074_656b_636f_7362_6577 => Ok(Capability::WebSocket),
                0x0065_7665_6973 => Ok(Capability::Sieve),
                0x626f_6c62 => Ok(Capability::Blob),
                0x0061_746f_7571 => Ok(Capability::Quota),
                _ => Err(parser.error_capability()),
            },
            Err(Error::Method(_)) => Err(parser.error_capability()),
            Err(err @ Error::Request(_)) => Err(err),
        }
    }
}

impl<'x> Parser<'x> {
    fn error_capability(&mut self) -> Error {
        if self.is_eof || self.skip_string() {
            Error::Request(RequestError::unknown_capability(&String::from_utf8_lossy(
                self.bytes[self.pos_marker..self.pos - 1].as_ref(),
            )))
        } else {
            self.error_unterminated()
        }
    }
}
