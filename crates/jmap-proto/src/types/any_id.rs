/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
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
