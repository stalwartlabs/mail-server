/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{Server, auth::AccessToken};
use directory::{
    QueryBy, Type,
    backend::internal::{PrincipalField, manage::ChangedPrincipals},
};
use jmap_proto::{
    error::set::SetError,
    types::{
        acl::Acl,
        collection::Collection,
        property::Property,
        value::{AclGrant, MaybePatchValue, Value},
    },
};
use store::{ValueKey, query::acl::AclQuery, roaring::RoaringBitmap, write::ValueClass};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

pub trait AclMethods: Sync + Send {
    fn shared_documents(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: Collection,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn shared_messages(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn owned_or_shared_documents(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn owned_or_shared_messages(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn has_access_to_document(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: impl Into<u8> + Send,
        to_document_id: u32,
        check_acls: impl Into<Bitmap<Acl>> + Send,
    ) -> impl Future<Output = trc::Result<bool>> + Send;

    fn acl_set(
        &self,
        changes: &mut Vec<AclGrant>,
        current: Option<&[AclGrant]>,
        acl_changes: MaybePatchValue,
    ) -> impl Future<Output = Result<(), SetError>> + Send;

    fn acl_get(
        &self,
        value: &[AclGrant],
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = Value> + Send;

    fn refresh_acls(
        &self,
        changes: &[AclGrant],
        current: Option<&[AclGrant]>,
    ) -> impl Future<Output = ()> + Send;

    fn map_acl_set(
        &self,
        acl_set: Vec<Value>,
    ) -> impl Future<Output = Result<Vec<AclGrant>, SetError>> + Send;

    fn map_acl_patch(
        &self,
        acl_patch: Vec<Value>,
    ) -> impl Future<Output = Result<(AclGrant, Option<bool>), SetError>> + Send;
}

impl AclMethods for Server {
    async fn shared_documents(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: Collection,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<RoaringBitmap> {
        let check_acls = check_acls.into();
        let mut document_ids = RoaringBitmap::new();
        let to_collection = u8::from(to_collection);
        for &grant_account_id in [access_token.primary_id]
            .iter()
            .chain(access_token.member_of.clone().iter())
        {
            for acl_item in self
                .core
                .storage
                .data
                .acl_query(AclQuery::SharedWith {
                    grant_account_id,
                    to_account_id,
                    to_collection,
                })
                .await
                .caused_by(trc::location!())?
            {
                let mut acls = Bitmap::<Acl>::from(acl_item.permissions);

                acls.intersection(&check_acls);
                if !acls.is_empty() {
                    document_ids.insert(acl_item.to_document_id);
                }
            }
        }

        Ok(document_ids)
    }

    async fn shared_messages(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<RoaringBitmap> {
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

    async fn owned_or_shared_documents(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<RoaringBitmap> {
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

    async fn owned_or_shared_messages(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<RoaringBitmap> {
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

    async fn has_access_to_document(
        &self,
        access_token: &AccessToken,
        to_account_id: u32,
        to_collection: impl Into<u8>,
        to_document_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> trc::Result<bool> {
        let to_collection = to_collection.into();
        let check_acls = check_acls.into();
        for &grant_account_id in [access_token.primary_id]
            .iter()
            .chain(access_token.member_of.clone().iter())
        {
            match self
                .core
                .storage
                .data
                .get_value::<u64>(ValueKey {
                    account_id: to_account_id,
                    collection: to_collection,
                    document_id: to_document_id,
                    class: ValueClass::Acl(grant_account_id),
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
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
        Ok(false)
    }

    async fn acl_set(
        &self,
        changes: &mut Vec<AclGrant>,
        current: Option<&[AclGrant]>,
        acl_changes: MaybePatchValue,
    ) -> Result<(), SetError> {
        match acl_changes {
            MaybePatchValue::Value(Value::List(values)) => {
                *changes = self.map_acl_set(values).await?;
            }
            MaybePatchValue::Patch(patch) => {
                let (mut patch, is_update) = self.map_acl_patch(patch).await?;
                if let Some(changes_) = current {
                    *changes = changes_.to_vec();
                }

                if let Some(is_set) = is_update {
                    if !patch.grants.is_empty() {
                        if let Some(acl_item) = changes
                            .iter_mut()
                            .find(|item| item.account_id == patch.account_id)
                        {
                            let item = patch.grants.pop().unwrap();
                            if is_set {
                                acl_item.grants.insert(item);
                            } else {
                                acl_item.grants.remove(item);
                                if acl_item.grants.is_empty() {
                                    changes.retain(|item| item.account_id != patch.account_id);
                                }
                            }
                        } else if is_set {
                            changes.push(patch);
                        }
                    }
                } else if !patch.grants.is_empty() {
                    if let Some(acl_item) = changes
                        .iter_mut()
                        .find(|item| item.account_id == patch.account_id)
                    {
                        acl_item.grants = patch.grants;
                    } else {
                        changes.push(patch);
                    }
                } else {
                    changes.retain(|item| item.account_id != patch.account_id);
                }
            }
            _ => {
                return Err(SetError::invalid_properties()
                    .with_property(Property::Acl)
                    .with_description("Invalid ACL property."));
            }
        }
        Ok(())
    }

    async fn acl_get(
        &self,
        value: &[AclGrant],
        access_token: &AccessToken,
        account_id: u32,
    ) -> Value {
        if access_token.is_member(account_id)
            || value.iter().any(|item| {
                access_token.is_member(item.account_id) && item.grants.contains(Acl::Administer)
            })
        {
            let mut acl_obj = jmap_proto::types::value::Object::with_capacity(value.len() / 2);
            for item in value {
                if let Some(mut principal) = self
                    .core
                    .storage
                    .directory
                    .query(QueryBy::Id(item.account_id), false)
                    .await
                    .unwrap_or_default()
                {
                    acl_obj.append(
                        Property::_T(principal.take_str(PrincipalField::Name).unwrap_or_default()),
                        item.grants
                            .map(|acl_item| Value::Text(acl_item.to_string()))
                            .collect::<Vec<_>>(),
                    );
                }
            }

            Value::Object(acl_obj)
        } else {
            Value::Null
        }
    }

    async fn refresh_acls(&self, acl_changes: &[AclGrant], current: Option<&[AclGrant]>) {
        let mut changed_principals = ChangedPrincipals::new();
        if let Some(acl_current) = current {
            for current_item in acl_current {
                let mut invalidate = true;
                for change_item in acl_changes {
                    if change_item.account_id == current_item.account_id {
                        invalidate = change_item.grants != current_item.grants;
                        break;
                    }
                }
                if invalidate {
                    changed_principals.add_change(
                        current_item.account_id,
                        Type::Individual,
                        PrincipalField::EnabledPermissions,
                    );
                }
            }

            for change_item in acl_changes {
                let mut invalidate = true;
                for current_item in acl_current {
                    if change_item.account_id == current_item.account_id {
                        invalidate = change_item.grants != current_item.grants;
                        break;
                    }
                }
                if invalidate {
                    changed_principals.add_change(
                        change_item.account_id,
                        Type::Individual,
                        PrincipalField::EnabledPermissions,
                    );
                }
            }
        } else {
            for value in acl_changes {
                changed_principals.add_change(
                    value.account_id,
                    Type::Individual,
                    PrincipalField::EnabledPermissions,
                );
            }
        }

        self.increment_token_revision(changed_principals).await;
    }

    async fn map_acl_set(&self, acl_set: Vec<Value>) -> Result<Vec<AclGrant>, SetError> {
        let mut acls = Vec::with_capacity(acl_set.len() / 2);
        for item in acl_set.chunks_exact(2) {
            if let (Value::Text(account_name), Value::UnsignedInt(grants)) = (&item[0], &item[1]) {
                match self
                    .core
                    .storage
                    .directory
                    .query(QueryBy::Name(account_name), false)
                    .await
                {
                    Ok(Some(principal)) => {
                        acls.push(AclGrant {
                            account_id: principal.id(),
                            grants: Bitmap::from(*grants),
                        });
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
            } else {
                return Err(SetError::invalid_properties()
                    .with_property(Property::Acl)
                    .with_description("Invalid ACL value found."));
            }
        }

        Ok(acls)
    }

    async fn map_acl_patch(
        &self,
        acl_patch: Vec<Value>,
    ) -> Result<(AclGrant, Option<bool>), SetError> {
        if let (Value::Text(account_name), Value::UnsignedInt(grants)) =
            (&acl_patch[0], &acl_patch[1])
        {
            match self
                .core
                .storage
                .directory
                .query(QueryBy::Name(account_name), false)
                .await
            {
                Ok(Some(principal)) => Ok((
                    AclGrant {
                        account_id: principal.id(),
                        grants: Bitmap::from(*grants),
                    },
                    acl_patch.get(2).map(|v| v.as_bool().unwrap_or(false)),
                )),
                Ok(None) => Err(SetError::invalid_properties()
                    .with_property(Property::Acl)
                    .with_description(format!("Account {account_name} does not exist."))),
                _ => Err(SetError::forbidden()
                    .with_property(Property::Acl)
                    .with_description("Temporary server failure during lookup")),
            }
        } else {
            Err(SetError::invalid_properties()
                .with_property(Property::Acl)
                .with_description("Invalid ACL value found."))
        }
    }
}

pub trait EffectiveAcl {
    fn effective_acl(&self, access_token: &AccessToken) -> Bitmap<Acl>;
}

impl EffectiveAcl for Vec<AclGrant> {
    fn effective_acl(&self, access_token: &AccessToken) -> Bitmap<Acl> {
        let mut acl = Bitmap::<Acl>::new();
        for item in self {
            if access_token.is_member(item.account_id) {
                acl.union(&item.grants);
            }
        }

        acl
    }
}
