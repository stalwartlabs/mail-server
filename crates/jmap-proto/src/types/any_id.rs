/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
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

use crate::{
    parser::{json::Parser, JsonObjectParser},
    request::reference::MaybeReference,
};

use super::{blob::BlobId, id::Id, value::Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyId {
    Id(Id),
    Blob(BlobId),
}

impl AnyId {
    pub fn as_id(&self) -> Option<&Id> {
        match self {
            AnyId::Id(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_blob_id(&self) -> Option<&BlobId> {
        match self {
            AnyId::Blob(id) => Some(id),
            _ => None,
        }
    }

    pub fn into_id(self) -> Option<Id> {
        match self {
            AnyId::Id(id) => Some(id),
            _ => None,
        }
    }

    pub fn into_blob_id(self) -> Option<BlobId> {
        match self {
            AnyId::Blob(id) => Some(id),
            _ => None,
        }
    }
}

impl From<Id> for AnyId {
    fn from(id: Id) -> Self {
        Self::Id(id)
    }
}

impl From<BlobId> for AnyId {
    fn from(id: BlobId) -> Self {
        Self::Blob(id)
    }
}

impl From<MaybeReference<Id, String>> for MaybeReference<AnyId, String> {
    fn from(value: MaybeReference<Id, String>) -> Self {
        match value {
            MaybeReference::Value(value) => MaybeReference::Value(value.into()),
            MaybeReference::Reference(reference) => MaybeReference::Reference(reference),
        }
    }
}

impl From<MaybeReference<BlobId, String>> for MaybeReference<AnyId, String> {
    fn from(value: MaybeReference<BlobId, String>) -> Self {
        match value {
            MaybeReference::Value(value) => MaybeReference::Value(value.into()),
            MaybeReference::Reference(reference) => MaybeReference::Reference(reference),
        }
    }
}

impl From<AnyId> for Value {
    fn from(value: AnyId) -> Self {
        match value {
            AnyId::Id(id) => Value::Id(id),
            AnyId::Blob(blob_id) => Value::BlobId(blob_id),
        }
    }
}

impl From<&AnyId> for Value {
    fn from(value: &AnyId) -> Self {
        match value {
            AnyId::Id(id) => Value::Id(*id),
            AnyId::Blob(blob_id) => Value::BlobId(blob_id.clone()),
        }
    }
}

impl JsonObjectParser for AnyId {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut id = Vec::with_capacity(16);

        while let Some(ch) = parser.next_unescaped()? {
            id.push(ch);
        }

        if id.is_empty() {
            return Err(parser.error_value());
        }

        BlobId::from_base32(&id)
            .map(AnyId::Blob)
            .or_else(|| Id::from_bytes(&id).map(AnyId::Id))
            .ok_or_else(|| parser.error_value())
    }
}

impl serde::Serialize for AnyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            AnyId::Id(id) => id.serialize(serializer),
            AnyId::Blob(id) => id.serialize(serializer),
        }
    }
}
