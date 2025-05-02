/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::WebDavTest;
use crate::webdav::GenerateTestDavResource;
use dav_proto::Depth;
use groupware::DavResourceName;
use hyper::StatusCode;

pub async fn test(test: &WebDavTest) {
    let client = test.client("john");

    for resource_type in [
        DavResourceName::File,
        DavResourceName::Cal,
        DavResourceName::Card,
    ] {
        println!(
            "Running REPORT sync-collection tests ({})...",
            resource_type.base_path()
        );
        let user_base_path = format!("{}/john", resource_type.base_path());

        // Test 1: Initial sync
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, ["D:getetag"])
            .await;
        assert_eq!(
            response.hrefs().len(),
            if resource_type == DavResourceName::File {
                1
            } else {
                2
            },
            "{:?}",
            response.hrefs()
        );
        let sync_token_1 = response.sync_token().to_string();

        // Test 2: No changes since last sync
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_1,
                Depth::Infinity,
                ["D:getetag"],
            )
            .await;
        assert_eq!(response.hrefs(), Vec::<String>::new());

        // Test 3: Create a collection and make sure it is synced
        let new_collection = format!("{}/new-collection/", user_base_path);
        client
            .mkcol("MKCOL", &new_collection, [], [])
            .await
            .with_status(StatusCode::CREATED);
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_1,
                Depth::Infinity,
                ["D:getetag"],
            )
            .await;
        assert_eq!(response.hrefs(), vec![new_collection.clone()]);
        let sync_token_2 = response.sync_token().to_string();

        // Test 4: Create a file and make sure it is synced
        let new_file = format!("{new_collection}new-file");
        let contents = resource_type.generate();
        client
            .request("PUT", &new_file, &contents)
            .await
            .with_status(StatusCode::CREATED);
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_1,
                Depth::Infinity,
                ["D:getetag"],
            )
            .await;
        assert_eq!(
            response.hrefs(),
            vec![new_collection.clone(), new_file.clone()]
        );
        let sync_token_3 = response.sync_token().to_string();
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_2,
                Depth::Infinity,
                ["D:getetag"],
            )
            .await;
        assert_eq!(response.hrefs(), vec![new_file.clone()]);

        // Test 5: sync-token with Depth 1
        let response = client
            .sync_collection(&user_base_path, &sync_token_1, Depth::One, ["D:getetag"])
            .await;
        assert_eq!(response.hrefs(), vec![new_collection.clone()]);

        // Test 6: sync-token with Depth 0
        let response = client
            .sync_collection(&new_collection, &sync_token_1, Depth::Zero, ["D:getetag"])
            .await;
        assert_eq!(response.hrefs(), vec![new_collection.clone()]);

        // Test 7: Outdated sync-token in If header should fail
        let new_file2 = format!("{new_collection}new-file2");
        let contents = resource_type.generate();
        let condition = format!("(<{sync_token_2}>)");
        client
            .request_with_headers(
                "PUT",
                &new_file2,
                [("if", condition.as_str())],
                contents.as_str(),
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_empty_body();

        // Test 8: Correct sync-token in If header should work
        let condition = format!("(<{sync_token_3}>)");
        client
            .request_with_headers(
                "PUT",
                &new_file2,
                [("if", condition.as_str())],
                contents.as_str(),
            )
            .await
            .with_status(StatusCode::CREATED)
            .with_empty_body();

        client
            .request("DELETE", &new_collection, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}
