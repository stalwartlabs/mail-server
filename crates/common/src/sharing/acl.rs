/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::{
    QueryBy, Type,
    backend::internal::{
        PrincipalField,
        manage::{ChangedPrincipals, ManageDirectory},
    },
};
use jmap_proto::{
    error::set::SetError,
    types::{
        acl::Acl,
        property::Property,
        value::{AclGrant, ArchivedAclGrant, MaybePatchValue, Value},
    },
};
use utils::map::bitmap::Bitmap;

use crate::{Server, auth::AccessToken};

impl Server {
    pub async fn acl_set(
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

    pub async fn acl_get(
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
                if let Some(name) = self
                    .store()
                    .get_principal_name(item.account_id)
                    .await
                    .unwrap_or_default()
                {
                    acl_obj.append(
                        Property::_T(name),
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

    pub async fn refresh_acls(&self, acl_changes: &[AclGrant], current: Option<&[AclGrant]>) {
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

    pub async fn refresh_archived_acls(
        &self,
        acl_changes: &[AclGrant],
        acl_current: &[ArchivedAclGrant],
    ) {
        let mut changed_principals = ChangedPrincipals::new();
        for current_item in acl_current.iter() {
            let mut invalidate = true;
            for change_item in acl_changes {
                if change_item.account_id == current_item.account_id {
                    invalidate = change_item.grants != current_item.grants;
                    break;
                }
            }
            if invalidate {
                changed_principals.add_change(
                    current_item.account_id.to_native(),
                    Type::Individual,
                    PrincipalField::EnabledPermissions,
                );
            }
        }

        for change_item in acl_changes {
            let mut invalidate = true;
            for current_item in acl_current.iter() {
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

        self.increment_token_revision(changed_principals).await;
    }

    pub async fn map_acl_set(&self, acl_set: Vec<Value>) -> Result<Vec<AclGrant>, SetError> {
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

    pub async fn map_acl_patch(
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
