/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use common::{
    auth::{AccessToken, TenantInfo},
    ipc::{DeliveryResult, IngestMessage},
};
use directory::{
    backend::internal::{PrincipalField, PrincipalUpdate, PrincipalValue},
    Permission, Principal, Type,
};
use jmap::{services::ingest::MailDelivery, JmapMethods};
use utils::BlobHash;

use crate::jmap::assert_is_empty;

use super::{enterprise::List, JMAPTest, ManagementApi};

pub async fn test(params: &JMAPTest) {
    println!("Running permissions tests...");
    let server = params.server.clone();

    // Prepare management API
    let api = ManagementApi::new(8899, "admin", "secret");

    // Create a user with the default 'user' role
    let account_id = api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Individual)
                .with_field(PrincipalField::Name, "role_player")
                .with_field(PrincipalField::Roles, vec!["user".to_string()])
                .with_field(
                    PrincipalField::DisabledPermissions,
                    vec![Permission::Pop3Dele.name().to_string()],
                ),
        )
        .await
        .unwrap()
        .unwrap_data();
    server
        .get_access_token(account_id)
        .await
        .unwrap()
        .validate_permissions(
            Permission::all().filter(|p| p.is_user_permission() && *p != Permission::Pop3Dele),
        );

    // Create multiple roles
    for (role, permissions, parent_role) in &[
        (
            "pop3_user",
            vec![Permission::Pop3Authenticate, Permission::Pop3List],
            vec![],
        ),
        (
            "imap_user",
            vec![Permission::ImapAuthenticate, Permission::ImapList],
            vec![],
        ),
        (
            "jmap_user",
            vec![
                Permission::JmapEmailQuery,
                Permission::AuthenticateOauth,
                Permission::ManageEncryption,
            ],
            vec![],
        ),
        (
            "email_user",
            vec![Permission::EmailSend, Permission::EmailReceive],
            vec!["pop3_user", "imap_user", "jmap_user"],
        ),
    ] {
        api.post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Role)
                .with_field(PrincipalField::Name, role.to_string())
                .with_field(
                    PrincipalField::EnabledPermissions,
                    permissions
                        .iter()
                        .map(|p| p.name().to_string())
                        .collect::<Vec<_>>(),
                )
                .with_field(
                    PrincipalField::Roles,
                    parent_role
                        .iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>(),
                ),
        )
        .await
        .unwrap()
        .unwrap_data();
    }

    // Update email_user role
    api.patch::<()>(
        "/api/principal/email_user",
        &vec![PrincipalUpdate::add_item(
            PrincipalField::DisabledPermissions,
            PrincipalValue::String(Permission::ManageEncryption.name().to_string()),
        )],
    )
    .await
    .unwrap()
    .unwrap_data();

    // Update the user role to the nested 'email_user' role
    api.patch::<()>(
        "/api/principal/role_player",
        &vec![PrincipalUpdate::set(
            PrincipalField::Roles,
            PrincipalValue::StringList(vec!["email_user".to_string()]),
        )],
    )
    .await
    .unwrap()
    .unwrap_data();
    server
        .get_access_token(account_id)
        .await
        .unwrap()
        .validate_permissions([
            Permission::EmailSend,
            Permission::EmailReceive,
            Permission::JmapEmailQuery,
            Permission::AuthenticateOauth,
            Permission::ImapAuthenticate,
            Permission::ImapList,
            Permission::Pop3Authenticate,
            Permission::Pop3List,
        ]);

    // Query all principals
    api.get::<List<Principal>>("/api/principal")
        .await
        .unwrap()
        .unwrap_data()
        .assert_count(6)
        .assert_exists(
            "admin",
            Type::Individual,
            [
                (PrincipalField::Roles, &["admin"][..]),
                (PrincipalField::Members, &[][..]),
                (PrincipalField::EnabledPermissions, &[][..]),
                (PrincipalField::DisabledPermissions, &[][..]),
            ],
        )
        .assert_exists(
            "role_player",
            Type::Individual,
            [
                (PrincipalField::Roles, &["email_user"][..]),
                (PrincipalField::Members, &[][..]),
                (PrincipalField::EnabledPermissions, &[][..]),
                (
                    PrincipalField::DisabledPermissions,
                    &[Permission::Pop3Dele.name()][..],
                ),
            ],
        )
        .assert_exists(
            "email_user",
            Type::Role,
            [
                (
                    PrincipalField::Roles,
                    &["pop3_user", "imap_user", "jmap_user"][..],
                ),
                (PrincipalField::Members, &["role_player"][..]),
                (
                    PrincipalField::EnabledPermissions,
                    &[
                        Permission::EmailReceive.name(),
                        Permission::EmailSend.name(),
                    ][..],
                ),
                (
                    PrincipalField::DisabledPermissions,
                    &[Permission::ManageEncryption.name()][..],
                ),
            ],
        )
        .assert_exists(
            "pop3_user",
            Type::Role,
            [
                (PrincipalField::Roles, &[][..]),
                (PrincipalField::Members, &["email_user"][..]),
                (
                    PrincipalField::EnabledPermissions,
                    &[
                        Permission::Pop3Authenticate.name(),
                        Permission::Pop3List.name(),
                    ][..],
                ),
                (PrincipalField::DisabledPermissions, &[][..]),
            ],
        )
        .assert_exists(
            "imap_user",
            Type::Role,
            [
                (PrincipalField::Roles, &[][..]),
                (PrincipalField::Members, &["email_user"][..]),
                (
                    PrincipalField::EnabledPermissions,
                    &[
                        Permission::ImapAuthenticate.name(),
                        Permission::ImapList.name(),
                    ][..],
                ),
                (PrincipalField::DisabledPermissions, &[][..]),
            ],
        )
        .assert_exists(
            "jmap_user",
            Type::Role,
            [
                (PrincipalField::Roles, &[][..]),
                (PrincipalField::Members, &["email_user"][..]),
                (
                    PrincipalField::EnabledPermissions,
                    &[
                        Permission::JmapEmailQuery.name(),
                        Permission::AuthenticateOauth.name(),
                        Permission::ManageEncryption.name(),
                    ][..],
                ),
                (PrincipalField::DisabledPermissions, &[][..]),
            ],
        );

    // Create new tenants
    let tenant_id = api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Tenant)
                .with_field(PrincipalField::Name, "foobar")
                .with_field(
                    PrincipalField::Roles,
                    vec!["tenant-admin".to_string(), "user".to_string()],
                )
                .with_field(
                    PrincipalField::Quota,
                    PrincipalValue::IntegerList(vec![TENANT_QUOTA, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]),
                ),
        )
        .await
        .unwrap()
        .unwrap_data();
    let other_tenant_id = api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Tenant)
                .with_field(PrincipalField::Name, "xanadu")
                .with_field(
                    PrincipalField::Roles,
                    vec!["tenant-admin".to_string(), "user".to_string()],
                ),
        )
        .await
        .unwrap()
        .unwrap_data();

    // Creating a tenant without a valid domain should fail
    api.post::<u32>(
        "/api/principal",
        &Principal::new(u32::MAX, Type::Individual)
            .with_field(PrincipalField::Name, "admin-foobar")
            .with_field(PrincipalField::Roles, vec!["tenant-admin".to_string()])
            .with_field(
                PrincipalField::Secrets,
                PrincipalValue::String("mytenantpass".to_string()),
            )
            .with_field(
                PrincipalField::Tenant,
                PrincipalValue::String("foobar".to_string()),
            ),
    )
    .await
    .unwrap()
    .expect_error("Principal name must include a valid domain assigned to the tenant");

    // Create domain for the tenant and one outside the tenant
    api.post::<u32>(
        "/api/principal",
        &Principal::new(u32::MAX, Type::Domain)
            .with_field(PrincipalField::Name, "foobar.org")
            .with_field(
                PrincipalField::Tenant,
                PrincipalValue::String("foobar".to_string()),
            ),
    )
    .await
    .unwrap()
    .unwrap_data();
    api.post::<u32>(
        "/api/principal",
        &Principal::new(u32::MAX, Type::Domain).with_field(PrincipalField::Name, "example.org"),
    )
    .await
    .unwrap()
    .unwrap_data();

    // Create tenant admin
    let tenant_admin_id = api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Individual)
                .with_field(PrincipalField::Name, "admin@foobar.org")
                .with_field(PrincipalField::Roles, vec!["tenant-admin".to_string()])
                .with_field(
                    PrincipalField::Secrets,
                    PrincipalValue::String("mytenantpass".to_string()),
                )
                .with_field(
                    PrincipalField::Tenant,
                    PrincipalValue::String("foobar".to_string()),
                ),
        )
        .await
        .unwrap()
        .unwrap_data();

    // Verify permissions
    server
        .get_access_token(tenant_admin_id)
        .await
        .unwrap()
        .validate_permissions(Permission::all().filter(|p| p.is_tenant_admin_permission()))
        .validate_tenant(tenant_id, TENANT_QUOTA);

    // Prepare tenant admin API
    let tenant_api = ManagementApi::new(8899, "admin@foobar.org", "mytenantpass");

    // Tenant should not be able to create other tenants or modify its tenant id
    tenant_api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Tenant).with_field(PrincipalField::Name, "subfoobar"),
        )
        .await
        .unwrap()
        .expect_request_error("Forbidden");
    tenant_api
        .patch::<()>(
            "/api/principal/foobar",
            &vec![PrincipalUpdate::set(
                PrincipalField::Tenant,
                PrincipalValue::String("subfoobar".to_string()),
            )],
        )
        .await
        .unwrap()
        .expect_request_error("Forbidden");
    tenant_api
        .get::<()>("/api/principal/foobar")
        .await
        .unwrap()
        .expect_request_error("Forbidden");
    tenant_api
        .get::<()>("/api/principal?type=tenant")
        .await
        .unwrap()
        .expect_request_error("Forbidden");

    // Create a second domain for the tenant
    tenant_api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Domain).with_field(PrincipalField::Name, "foobar.com"),
        )
        .await
        .unwrap()
        .unwrap_data();

    // Creating a third domain should be limited by quota
    tenant_api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Domain).with_field(PrincipalField::Name, "foobar.net"),
        )
        .await
        .unwrap()
        .expect_request_error("Tenant quota exceeded");

    // Creating a tenant user without a valid domain or with a domain outside the tenant should fail
    for user in ["mytenantuser", "john@example.org"] {
        tenant_api
            .post::<u32>(
                "/api/principal",
                &Principal::new(u32::MAX, Type::Individual)
                    .with_field(PrincipalField::Name, user.to_string())
                    .with_field(PrincipalField::Roles, vec!["tenant-admin".to_string()]),
            )
            .await
            .unwrap()
            .expect_error("Principal name must include a valid domain assigned to the tenant");
    }

    // Create an account
    let tenant_user_id = tenant_api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Individual)
                .with_field(PrincipalField::Name, "john@foobar.org")
                .with_field(PrincipalField::Roles, vec!["admin".to_string()])
                .with_field(
                    PrincipalField::Secrets,
                    PrincipalValue::String("tenantpass".to_string()),
                )
                .with_field(
                    PrincipalField::Tenant,
                    PrincipalValue::String("xanadu".to_string()),
                ),
        )
        .await
        .unwrap()
        .unwrap_data();

    // Although super user privileges were used and a different tenant name was provided, this should be ignored
    server
        .get_access_token(tenant_user_id)
        .await
        .unwrap()
        .validate_permissions(
            Permission::all().filter(|p| p.is_tenant_admin_permission() || p.is_user_permission()),
        )
        .validate_tenant(tenant_id, TENANT_QUOTA);

    // Create a second account should be limited by quota
    tenant_api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Individual)
                .with_field(PrincipalField::Name, "jane@foobar.org")
                .with_field(PrincipalField::Roles, vec!["tenant-admin".to_string()]),
        )
        .await
        .unwrap()
        .expect_request_error("Tenant quota exceeded");

    // Create an tenant role
    tenant_api
        .post::<u32>(
            "/api/principal",
            &Principal::new(u32::MAX, Type::Role)
                .with_field(PrincipalField::Name, "no-mail-for-you@foobar.com")
                .with_field(
                    PrincipalField::DisabledPermissions,
                    vec![Permission::EmailReceive.name().to_string()],
                ),
        )
        .await
        .unwrap()
        .unwrap_data();

    // Assigning a role that does not belong to the tenant should fail
    tenant_api
        .patch::<()>(
            "/api/principal/john@foobar.org",
            &vec![PrincipalUpdate::add_item(
                PrincipalField::Roles,
                PrincipalValue::String("imap_user".to_string()),
            )],
        )
        .await
        .unwrap()
        .expect_error("notFound");

    // Add tenant defined role
    tenant_api
        .patch::<()>(
            "/api/principal/john@foobar.org",
            &vec![PrincipalUpdate::add_item(
                PrincipalField::Roles,
                PrincipalValue::String("no-mail-for-you@foobar.com".to_string()),
            )],
        )
        .await
        .unwrap()
        .unwrap_data();

    // Check updated permissions
    server
        .get_access_token(tenant_user_id)
        .await
        .unwrap()
        .validate_permissions(Permission::all().filter(|p| {
            (p.is_tenant_admin_permission() || p.is_user_permission())
                && *p != Permission::EmailReceive
        }));

    // Changing the tenant of a user should fail
    tenant_api
        .patch::<()>(
            "/api/principal/john@foobar.org",
            &vec![PrincipalUpdate::set(
                PrincipalField::Tenant,
                PrincipalValue::String("xanadu".to_string()),
            )],
        )
        .await
        .unwrap()
        .expect_request_error("Forbidden");

    // Renaming a tenant account without a valid domain should fail
    for user in ["john", "john@example.org"] {
        tenant_api
            .patch::<()>(
                "/api/principal/john@foobar.org",
                &vec![PrincipalUpdate::set(
                    PrincipalField::Name,
                    PrincipalValue::String(user.to_string()),
                )],
            )
            .await
            .unwrap()
            .expect_error("Principal name must include a valid domain assigned to the tenant");
    }

    // Rename the tenant account and add an email address
    tenant_api
        .patch::<()>(
            "/api/principal/john@foobar.org",
            &vec![
                PrincipalUpdate::set(
                    PrincipalField::Name,
                    PrincipalValue::String("john.doe@foobar.org".to_string()),
                ),
                PrincipalUpdate::add_item(
                    PrincipalField::Emails,
                    PrincipalValue::String("john@foobar.org".to_string()),
                ),
            ],
        )
        .await
        .unwrap()
        .unwrap_data();

    // Tenants should only see their own principals
    tenant_api
        .get::<List<Principal>>("/api/principal?types=individual,group,role,list")
        .await
        .unwrap()
        .unwrap_data()
        .assert_count(3)
        .assert_exists(
            "admin@foobar.org",
            Type::Individual,
            [
                (PrincipalField::Roles, &["tenant-admin"][..]),
                (PrincipalField::Members, &[][..]),
                (PrincipalField::EnabledPermissions, &[][..]),
                (PrincipalField::DisabledPermissions, &[][..]),
            ],
        )
        .assert_exists(
            "john.doe@foobar.org",
            Type::Individual,
            [
                (
                    PrincipalField::Roles,
                    &["admin", "no-mail-for-you@foobar.com"][..],
                ),
                (PrincipalField::Members, &[][..]),
                (PrincipalField::EnabledPermissions, &[][..]),
                (PrincipalField::DisabledPermissions, &[][..]),
            ],
        )
        .assert_exists(
            "no-mail-for-you@foobar.com",
            Type::Role,
            [
                (PrincipalField::Roles, &[][..]),
                (PrincipalField::Members, &["john.doe@foobar.org"][..]),
                (PrincipalField::EnabledPermissions, &[][..]),
                (
                    PrincipalField::DisabledPermissions,
                    &[Permission::EmailReceive.name()][..],
                ),
            ],
        );

    // John should not be allowed to receive email
    let message_blob = BlobHash::from(TEST_MESSAGE.as_bytes());
    server
        .blob_store()
        .put_blob(message_blob.as_ref(), TEST_MESSAGE.as_bytes())
        .await
        .unwrap();
    assert_eq!(
        server
            .deliver_message(IngestMessage {
                sender_address: "bill@foobar.org".to_string(),
                recipients: vec!["john@foobar.org".to_string()],
                message_blob: message_blob.clone(),
                message_size: TEST_MESSAGE.len(),
                session_id: 0,
            })
            .await,
        vec![DeliveryResult::PermanentFailure {
            code: [5, 5, 0],
            reason: "This account is not authorized to receive email.".into()
        }]
    );

    // Remove the restriction
    tenant_api
        .patch::<()>(
            "/api/principal/john.doe@foobar.org",
            &vec![PrincipalUpdate::remove_item(
                PrincipalField::Roles,
                PrincipalValue::String("no-mail-for-you@foobar.com".to_string()),
            )],
        )
        .await
        .unwrap()
        .unwrap_data();
    server
        .get_access_token(tenant_user_id)
        .await
        .unwrap()
        .validate_permissions(
            Permission::all().filter(|p| p.is_tenant_admin_permission() || p.is_user_permission()),
        );

    // Delivery should now succeed
    assert_eq!(
        server
            .deliver_message(IngestMessage {
                sender_address: "bill@foobar.org".to_string(),
                recipients: vec!["john@foobar.org".to_string()],
                message_blob: message_blob.clone(),
                message_size: TEST_MESSAGE.len(),
                session_id: 0,
            })
            .await,
        vec![DeliveryResult::Success]
    );

    // Quota for the tenant and user should be updated
    assert_eq!(
        server.get_used_quota(tenant_id).await.unwrap(),
        TEST_MESSAGE.len() as i64
    );
    assert_eq!(
        server.get_used_quota(tenant_user_id).await.unwrap(),
        TEST_MESSAGE.len() as i64
    );

    // Next delivery should fail due to tenant quota
    assert_eq!(
        server
            .deliver_message(IngestMessage {
                sender_address: "bill@foobar.org".to_string(),
                recipients: vec!["john@foobar.org".to_string()],
                message_blob,
                message_size: TEST_MESSAGE.len(),
                session_id: 0,
            })
            .await,
        vec![DeliveryResult::TemporaryFailure {
            reason: "Organization over quota.".into()
        }]
    );

    // Moving a user to another tenant should move its quota too
    api.patch::<()>(
        "/api/principal/john.doe@foobar.org",
        &vec![PrincipalUpdate::set(
            PrincipalField::Tenant,
            PrincipalValue::String("xanadu".to_string()),
        )],
    )
    .await
    .unwrap()
    .unwrap_data();

    assert_eq!(server.get_used_quota(tenant_id).await.unwrap(), 0);
    assert_eq!(
        server.get_used_quota(other_tenant_id).await.unwrap(),
        TEST_MESSAGE.len() as i64
    );

    // Deleting tenants with data should fail
    api.delete::<()>("/api/principal/xanadu")
        .await
        .unwrap()
        .expect_error("Tenant has members");

    // Delete user
    api.delete::<()>("/api/principal/john.doe@foobar.org")
        .await
        .unwrap()
        .unwrap_data();

    // Quota usage for tenant should be updated
    assert_eq!(server.get_used_quota(other_tenant_id).await.unwrap(), 0);

    // Delete tenant
    api.delete::<()>("/api/principal/xanadu")
        .await
        .unwrap()
        .unwrap_data();

    // Delete tenant information
    for query in [
        "/api/principal/no-mail-for-you@foobar.com",
        "/api/principal/admin@foobar.org",
        "/api/principal/foobar.org",
        "/api/principal/foobar.com",
    ] {
        api.delete::<()>(query).await.unwrap().unwrap_data();
    }

    // Delete tenant
    api.delete::<()>("/api/principal/foobar")
        .await
        .unwrap()
        .unwrap_data();

    assert_is_empty(server).await;
}

const TENANT_QUOTA: u64 = TEST_MESSAGE.len() as u64;
const TEST_MESSAGE: &str = concat!(
    "From: bill@foobar.org\r\n",
    "To: jdoe@foobar.com\r\n",
    "Subject: TPS Report\r\n",
    "\r\n",
    "I'm going to need those TPS reports ASAP. ",
    "So, if you could do that, that'd be great."
);

trait ValidatePrincipalList {
    fn assert_exists<'x>(
        self,
        name: &str,
        typ: Type,
        items: impl IntoIterator<Item = (PrincipalField, &'x [&'x str])>,
    ) -> Self;
    fn assert_count(self, count: usize) -> Self;
}

impl ValidatePrincipalList for List<Principal> {
    fn assert_exists<'x>(
        self,
        name: &str,
        typ: Type,
        items: impl IntoIterator<Item = (PrincipalField, &'x [&'x str])>,
    ) -> Self {
        for item in &self.items {
            if item.name() == name {
                item.validate(typ, items);
                return self;
            }
        }

        panic!("Principal not found: {}", name);
    }

    fn assert_count(self, count: usize) -> Self {
        assert_eq!(self.items.len(), count, "Principal count failed validation");
        assert_eq!(self.total, count, "Principal total failed validation");
        self
    }
}

trait ValidatePrincipal {
    fn validate<'x>(
        &self,
        typ: Type,
        items: impl IntoIterator<Item = (PrincipalField, &'x [&'x str])>,
    );
}

impl ValidatePrincipal for Principal {
    fn validate<'x>(
        &self,
        typ: Type,
        items: impl IntoIterator<Item = (PrincipalField, &'x [&'x str])>,
    ) {
        assert_eq!(self.typ(), typ, "Type failed validation");

        for (field, values) in items {
            match (
                self.get_str_array(field).filter(|v| !v.is_empty()),
                (!values.is_empty()).then_some(values),
            ) {
                (Some(values), Some(expected)) => {
                    assert_eq!(
                        values.iter().map(|s| s.as_str()).collect::<AHashSet<_>>(),
                        expected.iter().copied().collect::<AHashSet<_>>(),
                        "Field {field:?} failed validation: {values:?} != {expected:?}"
                    );
                }
                (None, None) => {}
                (values, expected) => {
                    panic!("Field {field:?} failed validation: {values:?} != {expected:?}");
                }
            }
        }
    }
}

trait ValidatePermissions {
    fn validate_permissions(
        self,
        expected_permissions: impl IntoIterator<Item = Permission>,
    ) -> Self;
    fn validate_tenant(self, tenant_id: u32, tenant_quota: u64) -> Self;
}

impl ValidatePermissions for AccessToken {
    fn validate_permissions(
        self,
        expected_permissions: impl IntoIterator<Item = Permission>,
    ) -> Self {
        let expected_permissions: AHashSet<_> = expected_permissions.into_iter().collect();

        let permissions = self.permissions();
        for permission in &permissions {
            assert!(
                expected_permissions.contains(permission),
                "Permission {:?} failed validation",
                permission
            );
        }
        assert_eq!(
            permissions.into_iter().collect::<AHashSet<_>>(),
            expected_permissions
        );

        for permission in Permission::all() {
            if self.has_permission(permission) {
                assert!(
                    expected_permissions.contains(&permission),
                    "Permission {:?} failed validation",
                    permission
                );
            }
        }
        self
    }

    fn validate_tenant(self, tenant_id: u32, tenant_quota: u64) -> Self {
        assert_eq!(
            self.tenant,
            Some(TenantInfo {
                id: tenant_id,
                quota: tenant_quota
            })
        );
        self
    }
}
