/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::{borrow::Cow, path::PathBuf};

use mail_send::Credentials;
use tokio::{fs, io::AsyncReadExt, sync::oneshot};

#[derive(Debug)]
pub enum DeliveryEvent {
    Ingest {
        message: IngestMessage,
        result_tx: oneshot::Sender<Vec<DeliveryResult>>,
    },
    Lookup(LookupItem),
    Stop,
}

#[derive(Debug)]
pub struct IngestMessage {
    pub sender_address: String,
    pub recipients: Vec<String>,
    pub message_path: PathBuf,
    pub message_size: usize,
}

#[derive(Debug, Clone)]
pub enum DeliveryResult {
    Success,
    TemporaryFailure {
        reason: Cow<'static, str>,
    },
    PermanentFailure {
        code: [u8; 3],
        reason: Cow<'static, str>,
    },
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Item {
    IsAccount(String),
    Authenticate(Credentials<String>),
    Verify(String),
    Expand(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    True,
    False,
    Values(Vec<String>),
}

#[derive(Debug)]
pub struct LookupItem {
    pub item: Item,
    pub result: oneshot::Sender<LookupResult>,
}

impl From<LookupResult> for bool {
    fn from(value: LookupResult) -> Self {
        matches!(value, LookupResult::True | LookupResult::Values(_))
    }
}

impl From<bool> for LookupResult {
    fn from(value: bool) -> Self {
        if value {
            LookupResult::True
        } else {
            LookupResult::False
        }
    }
}

impl From<Vec<String>> for LookupResult {
    fn from(value: Vec<String>) -> Self {
        if !value.is_empty() {
            LookupResult::Values(value)
        } else {
            LookupResult::False
        }
    }
}

impl core::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IsAccount(arg0) => f.debug_tuple("Rcpt").field(arg0).finish(),
            Self::Authenticate(_) => f.debug_tuple("Auth").finish(),
            Self::Expand(arg0) => f.debug_tuple("Expn").field(arg0).finish(),
            Self::Verify(arg0) => f.debug_tuple("Vrfy").field(arg0).finish(),
        }
    }
}

impl IngestMessage {
    pub async fn read_message(&self) -> Result<Vec<u8>, ()> {
        let mut raw_message = vec![0u8; self.message_size];
        let mut file = fs::File::open(&self.message_path).await.map_err(|err| {
            tracing::error!(
                context = "read_message",
                event = "error",
                "Failed to open message file {}: {}",
                self.message_path.display(),
                err
            );
        })?;
        file.read_exact(&mut raw_message).await.map_err(|err| {
            tracing::error!(
                context = "read_message",
                event = "error",
                "Failed to read {} bytes file {} from disk: {}",
                self.message_size,
                self.message_path.display(),
                err
            );
        })?;
        Ok(raw_message)
    }
}
