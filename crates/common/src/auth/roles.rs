/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::{Arc, LazyLock};

use ahash::AHashSet;
use directory::{
    backend::internal::{lookup::DirectoryStore, PrincipalField},
    Permission, Permissions, QueryBy, ROLE_ADMIN, ROLE_TENANT_ADMIN, ROLE_USER,
};
use trc::AddContext;

use crate::Server;

#[derive(Debug, Clone, Default)]
pub struct RolePermissions {
    pub enabled: Permissions,
    pub disabled: Permissions,
}

static USER_PERMISSIONS: LazyLock<Arc<RolePermissions>> = LazyLock::new(user_permissions);
static ADMIN_PERMISSIONS: LazyLock<Arc<RolePermissions>> = LazyLock::new(admin_permissions);
static TENANT_ADMIN_PERMISSIONS: LazyLock<Arc<RolePermissions>> =
    LazyLock::new(tenant_admin_permissions);

impl Server {
    pub async fn get_role_permissions(&self, role_id: u32) -> trc::Result<Arc<RolePermissions>> {
        match role_id {
            ROLE_USER => Ok(USER_PERMISSIONS.clone()),
            ROLE_ADMIN => Ok(ADMIN_PERMISSIONS.clone()),
            ROLE_TENANT_ADMIN => Ok(TENANT_ADMIN_PERMISSIONS.clone()),
            role_id => {
                if let Some(role_permissions) = self.inner.data.permissions.get(&role_id) {
                    Ok(role_permissions.clone())
                } else {
                    self.build_role_permissions(role_id).await
                }
            }
        }
    }

    async fn build_role_permissions(&self, role_id: u32) -> trc::Result<Arc<RolePermissions>> {
        let mut role_ids = vec![role_id as u64].into_iter();
        let mut role_ids_stack = vec![];
        let mut fetched_role_ids = AHashSet::new();
        let mut return_permissions = RolePermissions::default();

        'outer: loop {
            if let Some(role_id) = role_ids.next() {
                let role_id = role_id as u32;

                // Skip if already fetched
                if !fetched_role_ids.insert(role_id) {
                    continue;
                }

                match role_id {
                    ROLE_USER => {
                        return_permissions.enabled.union(&USER_PERMISSIONS.enabled);
                        return_permissions
                            .disabled
                            .union(&USER_PERMISSIONS.disabled);
                    }
                    ROLE_ADMIN => {
                        return_permissions.enabled.union(&ADMIN_PERMISSIONS.enabled);
                        return_permissions
                            .disabled
                            .union(&ADMIN_PERMISSIONS.disabled);
                        break 'outer;
                    }
                    ROLE_TENANT_ADMIN => {
                        return_permissions
                            .enabled
                            .union(&TENANT_ADMIN_PERMISSIONS.enabled);
                        return_permissions
                            .disabled
                            .union(&TENANT_ADMIN_PERMISSIONS.disabled);
                    }
                    role_id => {
                        // Try with the cache
                        if let Some(role_permissions) = self.inner.data.permissions.get(&role_id) {
                            return_permissions.union(role_permissions.as_ref());
                        } else {
                            let mut role_permissions = RolePermissions::default();

                            // Obtain principal
                            let mut principal = self
                                .store()
                                .query(QueryBy::Id(role_id), true)
                                .await
                                .caused_by(trc::location!())?
                                .ok_or_else(|| {
                                    trc::SecurityEvent::Unauthorized
                                        .into_err()
                                        .details(
                                            "Principal not found while building role permissions",
                                        )
                                        .ctx(trc::Key::Id, role_id)
                                })?;

                            // Add permissions
                            for (permissions, field) in [
                                (
                                    &mut role_permissions.enabled,
                                    PrincipalField::EnabledPermissions,
                                ),
                                (
                                    &mut role_permissions.disabled,
                                    PrincipalField::DisabledPermissions,
                                ),
                            ] {
                                for permission in principal.iter_int(field) {
                                    let permission = permission as usize;
                                    if permission < Permission::COUNT {
                                        permissions.set(permission);
                                    }
                                }
                            }

                            // Add permissions
                            return_permissions.union(&role_permissions);

                            // Add parent roles
                            if let Some(parent_role_ids) = principal
                                .take_int_array(PrincipalField::Roles)
                                .filter(|r| !r.is_empty())
                            {
                                role_ids_stack.push(role_ids);
                                role_ids = parent_role_ids.into_iter();
                            } else {
                                // Cache role
                                self.inner
                                    .data
                                    .permissions
                                    .insert(role_id, Arc::new(role_permissions));
                            }
                        }
                    }
                }
            } else if let Some(prev_role_ids) = role_ids_stack.pop() {
                role_ids = prev_role_ids;
            } else {
                break;
            }
        }

        // Cache role
        let return_permissions = Arc::new(return_permissions);
        self.inner
            .data
            .permissions
            .insert(role_id, return_permissions.clone());
        Ok(return_permissions)
    }
}

impl RolePermissions {
    pub fn union(&mut self, other: &RolePermissions) {
        self.enabled.union(&other.enabled);
        self.disabled.union(&other.disabled);
    }

    pub fn finalize(mut self) -> Permissions {
        self.enabled.difference(&self.disabled);
        self.enabled
    }
}

fn tenant_admin_permissions() -> Arc<RolePermissions> {
    let mut permissions = RolePermissions {
        enabled: Permissions::new(),
        disabled: Permissions::new(),
    };

    for permission_id in 0..Permission::COUNT {
        let permission = Permission::from_id(permission_id).unwrap();
        if permission.is_tenant_admin_permission() {
            permissions.enabled.set(permission_id);
        }
    }

    Arc::new(permissions)
}

fn user_permissions() -> Arc<RolePermissions> {
    let mut permissions = RolePermissions {
        enabled: Permissions::new(),
        disabled: Permissions::new(),
    };

    for permission_id in 0..Permission::COUNT {
        let permission = Permission::from_id(permission_id).unwrap();
        if permission.is_user_permission() {
            permissions.enabled.set(permission_id);
        }
    }

    Arc::new(permissions)
}

fn admin_permissions() -> Arc<RolePermissions> {
    Arc::new(RolePermissions {
        enabled: Permissions::all(),
        disabled: Permissions::new(),
    })
}
