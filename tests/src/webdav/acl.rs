/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use dav_proto::schema::property::{DavProperty, WebDavProperty};
use groupware::DavResourceName;
use hyper::StatusCode;

use crate::webdav::GenerateTestDavResource;

use super::{DavResponse, DummyWebDavClient, WebDavTest};

pub async fn test(test: &WebDavTest) {
    let owner_client = test.client("bill");
    let sharee_client = test.client("john");

    for resource_type in [
        DavResourceName::File,
        DavResourceName::Cal,
        DavResourceName::Card,
    ] {
        println!("Running ACL tests ({})...", resource_type.base_path());
        let is_file = resource_type == DavResourceName::File;
        let sharee_principal = format!("{}/john/", DavResourceName::Principal.base_path());
        let sharee_base_path = format!("{}/john/", resource_type.base_path());
        let owner_principal = format!("{}/bill/", DavResourceName::Principal.base_path());
        let owner_base_path = format!("{}/bill/", resource_type.base_path());

        // Create a resource for the owner
        let owner_folder = format!("{owner_base_path}test-shared/");
        let owner_folder_private = format!("{owner_base_path}test-private/");
        let owner_file = format!("{owner_folder}test-file");
        let owner_file_content = resource_type.generate();
        let owner_file_private = format!("{owner_folder_private}test-file-private");
        let owner_file_content_private = resource_type.generate();
        for (folder, file, content) in [
            (&owner_folder, &owner_file, &owner_file_content),
            (
                &owner_folder_private,
                &owner_file_private,
                &owner_file_content_private,
            ),
        ] {
            owner_client
                .request("MKCOL", folder, "")
                .await
                .with_status(StatusCode::CREATED);
            owner_client
                .request("PUT", file, content)
                .await
                .with_status(StatusCode::CREATED);
        }

        // Create a resource for the sharee
        let sharee_folder = format!("{sharee_base_path}test-folder/");
        let sharee_file = format!("{sharee_folder}test-file");
        let sharee_file_content = resource_type.generate();
        sharee_client
            .request("MKCOL", &sharee_folder, "")
            .await
            .with_status(StatusCode::CREATED);
        sharee_client
            .request("PUT", &sharee_file, &sharee_file_content)
            .await
            .with_status(StatusCode::CREATED);

        // Test 1: Sharee should only see their own resources
        sharee_client
            .propfind_with_headers(
                resource_type.collection_path(),
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([sharee_base_path.as_str()]);

        // Test 2: Share a resource and make sure the root folder is visible
        owner_client
            .acl(&owner_folder, sharee_principal.as_str(), ["read"])
            .await
            .with_status(StatusCode::OK);
        if is_file {
            owner_client
                .acl(&owner_file, sharee_principal.as_str(), ["read"])
                .await
                .with_status(StatusCode::OK);
        }
        sharee_client
            .propfind_with_headers(
                resource_type.collection_path(),
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([sharee_base_path.as_str(), owner_base_path.as_str()]);

        // Test 3: Verify that only the shared resource is visible
        sharee_client
            .propfind_with_headers(
                &owner_base_path,
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([owner_folder.as_str()]);

        // Test 4: Verify that the sharee can access the shared resource
        sharee_client
            .propfind(
                &owner_folder,
                [DavProperty::WebDav(WebDavProperty::GetETag)],
            )
            .await
            .with_hrefs([owner_folder.as_str(), owner_file.as_str()]);
        sharee_client
            .request("GET", &owner_file, "")
            .await
            .with_status(StatusCode::OK)
            .with_body(&owner_file_content);

        // Test 5: Read ACL as owner
        let response = owner_client
            .propfind(&owner_folder, [DavProperty::WebDav(WebDavProperty::Acl)])
            .await;
        response
            .properties(&owner_folder)
            .get(DavProperty::WebDav(WebDavProperty::Acl))
            .with_values([
                format!("D:ace.D:principal.D:href:{sharee_principal}").as_str(),
                "D:ace.D:grant.D:privilege.D:read",
                "D:ace.D:grant.D:privilege.D:read-current-user-privilege-set",
            ]);

        // Test 6: acl-principal-prop-set REPORT
        let response = owner_client
            .request("REPORT", &owner_folder, ACL_PRINCIPAL_QUERY)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .into_propfind_response(None);
        response
            .properties(&sharee_principal)
            .get(DavProperty::WebDav(WebDavProperty::DisplayName))
            .with_values(["John Doe"]);

        // Test 7: Verify current-user-privilege-set and owner
        let response = sharee_client
            .propfind(
                &owner_folder,
                [
                    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
                    DavProperty::WebDav(WebDavProperty::Owner),
                ],
            )
            .await;
        for href in [owner_folder.as_str(), owner_file.as_str()] {
            let props = response.properties(href);
            props
                .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
                .with_values([
                    "D:privilege.D:read",
                    "D:privilege.D:read-current-user-privilege-set",
                ]);
            props
                .get(DavProperty::WebDav(WebDavProperty::Owner))
                .with_values([format!("D:href:{owner_principal}").as_str()]);
        }

        // Test 8: Write operations should fail
        for (path, dest, dest_copy) in [
            (
                &owner_folder,
                &sharee_folder,
                Some(format!("{sharee_base_path}copied/")),
            ),
            (&owner_file, &sharee_file, None),
        ] {
            sharee_client
                .proppatch(
                    path,
                    [(DavProperty::WebDav(WebDavProperty::DisplayName), "test")],
                    [],
                    [],
                )
                .await
                .with_status(StatusCode::FORBIDDEN);
            sharee_client
                .request("DELETE", path, "")
                .await
                .with_status(StatusCode::FORBIDDEN);
            sharee_client
                .request_with_headers("MOVE", path, [("destination", dest.as_str())], "")
                .await
                .with_status(StatusCode::FORBIDDEN);
            if let Some(dest_copy) = dest_copy {
                sharee_client
                    .request_with_headers("COPY", path, [("destination", dest_copy.as_str())], "")
                    .await
                    .with_status(StatusCode::CREATED);
            }
        }
        sharee_client
            .request("PUT", &owner_file, resource_type.generate())
            .await
            .with_status(StatusCode::FORBIDDEN);

        // Test 9: Grant write access to the sharee
        owner_client
            .acl(
                &owner_folder,
                sharee_principal.as_str(),
                ["read", "write-content", "write-properties"],
            )
            .await
            .with_status(StatusCode::OK);
        if is_file {
            owner_client
                .acl(
                    &owner_file,
                    sharee_principal.as_str(),
                    ["read", "write-content", "write-properties"],
                )
                .await
                .with_status(StatusCode::OK);
        }
        let response = owner_client
            .propfind(&owner_folder, [DavProperty::WebDav(WebDavProperty::Acl)])
            .await;
        response
            .properties(&owner_folder)
            .get(DavProperty::WebDav(WebDavProperty::Acl))
            .with_values([
                format!("D:ace.D:principal.D:href:{sharee_principal}").as_str(),
                "D:ace.D:grant.D:privilege.D:read",
                "D:ace.D:grant.D:privilege.D:read-current-user-privilege-set",
                "D:ace.D:grant.D:privilege.D:write-content",
                "D:ace.D:grant.D:privilege.D:write-properties",
            ]);
        let response = sharee_client
            .propfind(
                &owner_folder,
                [DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet)],
            )
            .await;
        for href in [owner_folder.as_str(), owner_file.as_str()] {
            response
                .properties(href)
                .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
                .with_values([
                    "D:privilege.D:read",
                    "D:privilege.D:read-current-user-privilege-set",
                    "D:privilege.D:write-content",
                    "D:privilege.D:write-properties",
                ]);
        }

        // Test 10: Delete operations should fail
        for (path, dest) in [(&owner_folder, &sharee_folder), (&owner_file, &sharee_file)] {
            sharee_client
                .proppatch(
                    path,
                    [(DavProperty::WebDav(WebDavProperty::DisplayName), "test")],
                    [],
                    [],
                )
                .await
                .with_status(StatusCode::MULTI_STATUS);
            sharee_client
                .request("DELETE", path, "")
                .await
                .with_status(StatusCode::FORBIDDEN);
            sharee_client
                .request_with_headers("MOVE", path, [("destination", dest.as_str())], "")
                .await
                .with_status(StatusCode::FORBIDDEN);
        }
        sharee_client
            .request("PUT", &owner_file, &owner_file_content)
            .await
            .with_status(StatusCode::NO_CONTENT);

        // Test 11: Grant delete access to the sharee and verify
        owner_client
            .acl(&owner_folder, sharee_principal.as_str(), ["read", "write"])
            .await
            .with_status(StatusCode::OK);
        if is_file {
            owner_client
                .acl(&owner_file, sharee_principal.as_str(), ["read", "write"])
                .await
                .with_status(StatusCode::OK);
        }
        sharee_client
            .request_with_headers(
                "MOVE",
                &owner_file,
                [("destination", sharee_file.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::NO_CONTENT);
        sharee_client
            .request("DELETE", &owner_folder, "")
            .await
            .with_status(StatusCode::NO_CONTENT);

        // Test 12: Share and unshare a resource
        owner_client
            .acl(&owner_folder_private, sharee_principal.as_str(), ["read"])
            .await
            .with_status(StatusCode::OK);
        sharee_client
            .propfind_with_headers(
                resource_type.collection_path(),
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([sharee_base_path.as_str(), owner_base_path.as_str()]);
        sharee_client
            .propfind_with_headers(
                &owner_base_path,
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([owner_folder_private.as_str()]);
        owner_client
            .acl(&owner_folder_private, sharee_principal.as_str(), [])
            .await
            .with_status(StatusCode::OK);
        sharee_client
            .propfind_with_headers(
                resource_type.collection_path(),
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([sharee_base_path.as_str()]);

        // Delete resources
        owner_client
            .request("DELETE", &owner_folder_private, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        sharee_client
            .request("DELETE", &sharee_folder, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        sharee_client
            .request("DELETE", &format!("{sharee_base_path}copied/"), "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    sharee_client.delete_default_containers().await;
    owner_client.delete_default_containers().await;
    test.assert_is_empty().await;
}

impl DummyWebDavClient {
    pub async fn acl<'x>(
        &self,
        query: &str,
        principal_href: &str,
        grant: impl IntoIterator<Item = &'x str>,
    ) -> DavResponse {
        let body = ACL_QUERY.replace("$HREF", principal_href).replace(
            "$GRANT",
            &grant.into_iter().fold(String::new(), |mut output, g| {
                use std::fmt::Write;
                let _ = write!(output, "<D:privilege><D:{g}/></D:privilege>");
                output
            }),
        );
        self.request("ACL", query, &body).await
    }
}

const ACL_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:acl xmlns:D="DAV:">
     <D:ace>
       <D:principal>
         <D:href>$HREF</D:href>
       </D:principal>
       <D:grant>
         $GRANT
       </D:grant>
     </D:ace>
   </D:acl>"#;

const ACL_PRINCIPAL_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:acl-principal-prop-set xmlns:D="DAV:">
     <D:prop>
       <D:displayname/>
     </D:prop>
   </D:acl-principal-prop-set>"#;
