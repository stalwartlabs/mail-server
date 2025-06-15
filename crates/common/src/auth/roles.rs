/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::{Arc, LazyLock};

use ahash::AHashSet;
use directory::{
    Permission, Permissions, QueryBy, ROLE_ADMIN, ROLE_TENANT_ADMIN, ROLE_USER,
    backend::internal::lookup::DirectoryStore,
};
use trc::AddContext;
use utils::cache::CacheItemWeight;

use crate::Server;

#[derive(Debug, Clone, Default)]
pub struct RolePermissions {
    pub enabled: Permissions,
    pub disabled: Permissions,
    pub revision: u64,
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
                let revision = self.fetch_token_revision(role_id).await;

                match self
                    .inner
                    .cache
                    .permissions
                    .get_value_or_guard_async(&role_id)
                    .await
                {
                    Ok(permissions) => {
                        if Some(permissions.revision) == revision {
                            Ok(permissions)
                        } else {
                            let permissions = self
                                .build_role_permissions(role_id, revision.unwrap_or(u64::MAX))
                                .await?;

                            self.inner
                                .cache
                                .permissions
                                .insert(role_id, permissions.clone());

                            Ok(permissions)
                        }
                    }
                    Err(guard) => {
                        let permissions = self
                            .build_role_permissions(role_id, revision.unwrap_or(u64::MAX))
                            .await?;
                        let _ = guard.insert(permissions.clone());
                        Ok(permissions)
                    }
                }
            }
        }
    }

    async fn build_role_permissions(
        &self,
        role_id: u32,
        revision: u64,
    ) -> trc::Result<Arc<RolePermissions>> {
        let mut role_ids = vec![role_id].into_iter();
        let mut role_ids_stack = vec![];
        let mut fetched_role_ids = AHashSet::new();
        let mut return_permissions = RolePermissions {
            revision,
            ..Default::default()
        };

        'outer: loop {
            if let Some(role_id) = role_ids.next() {
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
                        let revision = self.fetch_token_revision(role_id).await;
                        if let Some(role_permissions) = self
                            .inner
                            .cache
                            .permissions
                            .get(&role_id)
                            .filter(|p| Some(p.revision) == revision)
                        {
                            return_permissions.union(role_permissions.as_ref());
                        } else {
                            let mut role_permissions = RolePermissions {
                                revision: revision.unwrap_or(u64::MAX),
                                ..Default::default()
                            };

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
                            for permission in principal.permissions() {
                                if permission.grant {
                                    role_permissions.enabled.set(permission.permission.id());
                                } else {
                                    role_permissions.disabled.set(permission.permission.id());
                                }
                            }

                            // Add permissions
                            return_permissions.union(&role_permissions);

                            // Add parent roles
                            if let Some(parent_role_ids) =
                                principal.roles_mut().filter(|r| !r.is_empty())
                            {
                                role_ids_stack.push(role_ids);
                                role_ids = std::mem::take(parent_role_ids).into_iter();
                            } else {
                                // Cache role
                                self.inner
                                    .cache
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

        Ok(Arc::new(return_permissions))
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

    pub fn finalize_as_ref(&self) -> Permissions {
        let mut enabled = self.enabled.clone();
        enabled.difference(&self.disabled);
        enabled
    }
}

fn tenant_admin_permissions() -> Arc<RolePermissions> {
    let mut permissions = RolePermissions::default();

    for permission_id in 0..Permission::COUNT {
        let permission = Permission::from_id(permission_id).unwrap();
        if permission.is_tenant_admin_permission() {
            permissions.enabled.set(permission_id);
        }
    }

    Arc::new(permissions)
}

fn user_permissions() -> Arc<RolePermissions> {
    let mut permissions = RolePermissions::default();

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
        revision: 0,
    })
}

impl CacheItemWeight for RolePermissions {
    fn weight(&self) -> u64 {
        std::mem::size_of::<RolePermissions>() as u64
    }
}
