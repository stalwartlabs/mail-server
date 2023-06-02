/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use jmap_proto::{
    error::{method::MethodError, set::SetError},
    object::Object,
    types::{
        acl::Acl,
        collection::Collection,
        property::Property,
        value::{MaybePatchValue, Value},
    },
};
use store::{
    roaring::RoaringBitmap,
    write::{assert::HashedValue, key::DeserializeBigEndian},
    AclKey, Deserialize, Error,
};
use utils::map::bitmap::{Bitmap, BitmapItem};

use crate::JMAP;

use super::AccessToken;

impl JMAP {
    pub async fn update_access_token(&self, mut access_token: AccessToken) -> Option<AccessToken> {
        for &grant_account_id in [access_token.primary_id]
            .iter()
            .chain(access_token.member_of.clone().iter())
        {
            let from_key = AclKey {
                grant_account_id,
                to_account_id: 0,
                to_collection: 0,
                to_document_id: 0,
            };
            let to_key = AclKey {
                grant_account_id,
                to_account_id: u32::MAX,
                to_collection: u8::MAX,
                to_document_id: u32::MAX,
            };
            match self
                .store
                .iterate(
                    access_token,
                    from_key,
                    to_key,
                    false,
                    true,
                    |access_token, key, value| {
                        let acl_key = AclKey::deserialize(key)?;
                        if access_token.is_member(acl_key.to_account_id) {
                            return Ok(true);
                        }

                        let acl = Bitmap::<Acl>::from(u64::deserialize(value)?);
                        let collection = Collection::from(acl_key.to_collection);
                        if !collection.is_valid() {
                            return Err(Error::InternalError(format!(
                                "Found corrupted collection in key {key:?}"
                            )));
                        }

                        let mut collections: Bitmap<Collection> = Bitmap::new();
                        if acl.contains(Acl::Read) || acl.contains(Acl::Administer) {
                            collections.insert(collection);
                        }
                        if collection == Collection::Mailbox
                            && (acl.contains(Acl::ReadItems) || acl.contains(Acl::Administer))
                        {
                            collections.insert(Collection::Email);
                        }

                        if !collections.is_empty() {
                            if let Some((_, sharing)) = access_token
                                .access_to
                                .iter_mut()
                                .find(|(account_id, _)| *account_id == acl_key.to_account_id)
                            {
                                sharing.union(&collections);
                            } else {
                                access_token
                                    .access_to
                                    .push((acl_key.to_account_id, collections));
                            }
                        }

                        Ok(true)
                    },
                )
                .await
            {
                Ok(access_token_) => {
                    access_token = access_token_;
                }
                Err(err) => {
                    tracing::error!(
                        event = "error",
                        context = "shared_accounts",
                        error = ?err,
                        "Failed to iterate ACLs.");
                    return None;
                }
            }
        }
        access_token.into()
    }

    pub async fn shared_documents(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: Collection,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> Result<RoaringBitmap, MethodError> {
        let check_acls = check_acls.into();
        let mut document_ids = RoaringBitmap::new();
        let to_collection = u8::from(to_collection);
        for &grant_account_id in [access_token.primary_id]
            .iter()
            .chain(access_token.member_of.clone().iter())
        {
            let from_key = AclKey {
                grant_account_id,
                to_account_id,
                to_collection,
                to_document_id: 0,
            };
            let mut to_key = from_key;
            to_key.to_document_id = u32::MAX;

            match self
                .store
                .iterate(
                    document_ids,
                    from_key,
                    to_key,
                    false,
                    true,
                    move |document_ids, key, value| {
                        let mut acls = Bitmap::<Acl>::from(u64::deserialize(value)?);

                        acls.intersection(&check_acls);
                        if !acls.is_empty() {
                            document_ids.insert(
                                key.deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?,
                            );
                        }

                        Ok(true)
                    },
                )
                .await
            {
                Ok(document_ids_) => {
                    document_ids = document_ids_;
                }
                Err(err) => {
                    tracing::error!(
                    event = "error",
                    context = "shared_accounts",
                    error = ?err,
                    "Failed to iterate ACLs.");
                    return Err(MethodError::ServerPartialFail);
                }
            }
        }

        Ok(document_ids)
    }

    pub async fn shared_messages(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> Result<RoaringBitmap, MethodError> {
        let check_acls = check_acls.into();
        let shared_mailboxes = self
            .shared_documents(access_token, to_account_id, Collection::Mailbox, check_acls)
            .await?;
        if shared_mailboxes.is_empty() {
            return Ok(shared_mailboxes);
        }
        let mut shared_messages = RoaringBitmap::new();
        for mailbox_id in shared_mailboxes {
            if let Some(messages_in_mailbox) = self
                .get_tag(
                    to_account_id,
                    Collection::Email,
                    Property::MailboxIds,
                    mailbox_id,
                )
                .await?
            {
                shared_messages |= messages_in_mailbox;
            }
        }

        Ok(shared_messages)
    }

    pub async fn owned_or_shared_documents(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> Result<RoaringBitmap, MethodError> {
        let check_acls = check_acls.into();
        let mut document_ids = self
            .get_document_ids(account_id, collection)
            .await?
            .unwrap_or_default();
        if !document_ids.is_empty() && !access_token.is_member(account_id) {
            document_ids &= self
                .shared_documents(access_token, account_id, collection, check_acls)
                .await?;
        }
        Ok(document_ids)
    }

    pub async fn owned_or_shared_messages(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> Result<RoaringBitmap, MethodError> {
        let check_acls = check_acls.into();
        let mut document_ids = self
            .get_document_ids(account_id, Collection::Email)
            .await?
            .unwrap_or_default();
        if !document_ids.is_empty() && !access_token.is_member(account_id) {
            document_ids &= self
                .shared_messages(access_token, account_id, check_acls)
                .await?;
        }
        Ok(document_ids)
    }

    pub async fn has_access_to_document(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: impl Into<u8>,
        to_document_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> Result<bool, MethodError> {
        let to_collection = to_collection.into();
        let check_acls = check_acls.into();
        for &grant_account_id in [access_token.primary_id]
            .iter()
            .chain(access_token.member_of.clone().iter())
        {
            match self
                .store
                .get_value::<u64>(AclKey {
                    grant_account_id,
                    to_account_id,
                    to_collection,
                    to_document_id,
                })
                .await
            {
                Ok(Some(acls)) => {
                    let mut acls = Bitmap::<Acl>::from(acls);

                    acls.intersection(&check_acls);
                    if !acls.is_empty() {
                        return Ok(true);
                    }
                }
                Ok(None) => (),
                Err(err) => {
                    tracing::error!(
                    event = "error",
                    context = "has_access_to_document",
                    error = ?err,
                    "Failed to verify ACL.");
                    return Err(MethodError::ServerPartialFail);
                }
            }
        }
        Ok(false)
    }

    pub async fn acl_set(
        &self,
        changes: &mut Object<Value>,
        current: Option<&HashedValue<Object<Value>>>,
        acl_changes: MaybePatchValue,
    ) -> Result<(), SetError> {
        match acl_changes {
            MaybePatchValue::Value(Value::List(values)) => {
                changes.properties.set(
                    Property::Acl,
                    Value::List(self.map_acl_accounts(values).await?),
                );
            }
            MaybePatchValue::Patch(patch) => {
                let patch = self.map_acl_accounts(patch).await?;
                let acl = if let Value::List(acl) =
                    changes
                        .properties
                        .get_mut_or_insert_with(Property::Acl, || {
                            current
                                .and_then(|current| {
                                    current.inner.properties.get(&Property::Acl).cloned()
                                })
                                .unwrap_or_else(|| Value::List(Vec::new()))
                        }) {
                    acl
                } else {
                    return Err(SetError::invalid_properties()
                        .with_property(Property::Acl)
                        .with_description("Invalid ACL value found."));
                };
                let account_id = patch.first().unwrap().as_id().unwrap();
                match patch.len() {
                    2 => {
                        let acl_update = patch.last().unwrap().as_uint().unwrap();
                        if let Some(idx) =
                            acl.iter().position(|item| item.as_id() == Some(account_id))
                        {
                            if acl_update != 0 {
                                acl[idx + 1] = Value::UnsignedInt(acl_update);
                            } else if acl.len() > 2 {
                                acl.remove(idx);
                                acl.remove(idx);
                            } else {
                                acl.clear();
                            }
                        } else if acl_update != 0 {
                            acl.push(Value::Id(*account_id));
                            acl.push(Value::UnsignedInt(acl_update));
                        }
                    }
                    3 => {
                        let acl_item = Acl::from(patch[1].as_uint().unwrap());
                        let set = patch[2].as_bool().unwrap_or(false);
                        if let Some(idx) =
                            acl.iter().position(|item| item.as_id() == Some(account_id))
                        {
                            if let Some(Value::UnsignedInt(current)) = acl.get_mut(idx + 1) {
                                let mut bitmap = Bitmap::from(*current);
                                if set {
                                    bitmap.insert(acl_item);
                                } else {
                                    bitmap.remove(acl_item);
                                }
                                if !bitmap.is_empty() {
                                    *current = bitmap.into();
                                } else {
                                    acl.remove(idx);
                                    acl.remove(idx);
                                }
                            } else {
                                return Err(SetError::invalid_properties()
                                    .with_property(Property::Acl)
                                    .with_description("Invalid ACL value found."));
                            }
                        } else if set {
                            acl.push(Value::Id(*account_id));
                            acl.push(Value::UnsignedInt(Bitmap::new().with_item(acl_item).into()));
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => {
                return Err(SetError::invalid_properties()
                    .with_property(Property::Acl)
                    .with_description("Invalid ACL property."))
            }
        }
        Ok(())
    }

    pub async fn acl_get(
        &self,
        value: &[Value],
        access_token: &AccessToken,
        account_id: u32,
    ) -> Value {
        if access_token.is_member(account_id)
            || value.chunks_exact(2).any(|item| {
                access_token.is_member(
                    item.first()
                        .and_then(|v| v.as_id().map(|id| id.document_id()))
                        .unwrap_or(u32::MAX),
                ) && Bitmap::from(item.last().and_then(|a| a.as_uint()).unwrap_or_default())
                    .contains(Acl::Administer)
            })
        {
            let mut acl_obj = Object::with_capacity(value.len() / 2);
            for item in value.chunks_exact(2) {
                if let (Some(Value::Id(id)), Some(Value::UnsignedInt(acl_bits))) =
                    (item.first(), item.last())
                {
                    if let Some(account_name) = self
                        .directory
                        .principal_by_id(id.document_id())
                        .await
                        .unwrap_or_default()
                        .and_then(|p| {
                            if p.has_name() {
                                Some(p.name().to_string())
                            } else {
                                None
                            }
                        })
                    {
                        acl_obj.append(
                            Property::_T(account_name),
                            Bitmap::<Acl>::from(*acl_bits)
                                .map(|acl_item| Value::Text(acl_item.to_string()))
                                .collect::<Vec<_>>(),
                        );
                    }
                }
            }

            Value::Object(acl_obj)
        } else {
            Value::Null
        }
    }

    pub fn refresh_acls(
        &self,
        changes: &Object<Value>,
        current: &Option<HashedValue<Object<Value>>>,
    ) {
        if let Value::List(acl_changes) = changes.get(&Property::Acl) {
            let mut access_tokens = self.access_tokens.lock();
            if let Some(Value::List(acl_current)) = current
                .as_ref()
                .and_then(|current| current.inner.properties.get(&Property::Acl))
            {
                for current_item in acl_current.chunks_exact(2) {
                    let mut invalidate = true;
                    for change_item in acl_changes.chunks_exact(2) {
                        if change_item.first() == current_item.first() {
                            invalidate = change_item.last() != current_item.last();
                            break;
                        }
                    }
                    if invalidate {
                        if let Some(Value::Id(id)) = current_item.first() {
                            access_tokens.remove(&id.document_id());
                        }
                    }
                }

                for change_item in acl_changes.chunks_exact(2) {
                    let mut invalidate = true;
                    for current_item in acl_current.chunks_exact(2) {
                        if change_item.first() == current_item.first() {
                            invalidate = change_item.last() != current_item.last();
                            break;
                        }
                    }
                    if invalidate {
                        if let Some(Value::Id(id)) = change_item.first() {
                            access_tokens.remove(&id.document_id());
                        }
                    }
                }
            } else {
                for value in acl_changes {
                    if let Value::Id(id) = value {
                        access_tokens.remove(&id.document_id());
                    }
                }
            }
        }
    }

    async fn map_acl_accounts(&self, mut acl_set: Vec<Value>) -> Result<Vec<Value>, SetError> {
        for item in &mut acl_set {
            if let Value::Text(account_name) = item {
                match self.directory.principal_by_name(account_name).await {
                    Ok(Some(principal)) if principal.has_id() => {
                        *item = Value::Id(principal.id().into());
                    }
                    Ok(None) => {
                        return Err(SetError::invalid_properties()
                            .with_property(Property::Acl)
                            .with_description(format!("Account {account_name} does not exist.")));
                    }
                    _ => {
                        return Err(SetError::forbidden()
                            .with_property(Property::Acl)
                            .with_description("Temporary server failure during lookup"));
                    }
                }
            }
        }

        Ok(acl_set)
    }
}

pub trait EffectiveAcl {
    fn effective_acl(&self, access_token: &AccessToken) -> Bitmap<Acl>;
}

impl EffectiveAcl for Object<Value> {
    fn effective_acl(&self, access_token: &AccessToken) -> Bitmap<Acl> {
        let mut acl = Bitmap::<Acl>::new();
        if let Some(Value::List(permissions)) = self.properties.get(&Property::Acl) {
            for item in permissions.chunks(2) {
                if let (Some(Value::Id(account_id)), Some(Value::UnsignedInt(acl_bits))) =
                    (item.first(), item.last())
                {
                    if access_token.is_member(account_id.document_id()) {
                        acl.union(&Bitmap::from(*acl_bits));
                    }
                }
            }
        }

        acl
    }
}
