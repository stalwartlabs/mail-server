/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavResponse, WebDavTest};
use crate::webdav::GenerateTestDavResource;
use ahash::AHashSet;
use dav_proto::Depth;
use groupware::DavResourceName;
use hyper::StatusCode;

pub async fn test(test: &WebDavTest) {
    let client = test.client("jane");
    let mike_noquota = test.client("mike");

    for resource_type in [
        DavResourceName::File,
        DavResourceName::Cal,
        DavResourceName::Card,
    ] {
        println!("Running COPY/MOVE tests ({})...", resource_type.base_path());
        let user_base_path = format!("{}/jane", resource_type.base_path());
        let group_base_path = format!("{}/support", resource_type.base_path());
        let default_test_depth = if resource_type == DavResourceName::File {
            2
        } else {
            0
        };

        // Obtain sync token
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
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

        // Create nested files and folders
        let (hierarchy_root, mut hierarchy) = client
            .create_hierarchy(&user_base_path, default_test_depth, 2, 3)
            .await;
        let prev_sync_token = response.sync_token();
        let response = client
            .sync_collection(
                &user_base_path,
                prev_sync_token,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await;
        let sync_token = response.sync_token();
        let changed_hrefs = response.hrefs();
        assert_ne!(sync_token, prev_sync_token);
        assert_eq!(
            changed_hrefs,
            hierarchy.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(),
            "lengths {} & {}",
            changed_hrefs.len(),
            hierarchy.len()
        );
        client.validate_values(&hierarchy).await;

        // Delete cache an resync
        test.clear_cache();
        let response = client
            .sync_collection(
                &user_base_path,
                prev_sync_token,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await;
        let sync_token = response.sync_token();
        let changed_hrefs = response.hrefs();
        assert_ne!(sync_token, prev_sync_token);
        assert_eq!(
            changed_hrefs,
            hierarchy.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(),
            "lengths {} & {}",
            changed_hrefs.len(),
            hierarchy.len()
        );

        // Copying and moving to the same or root containers is invalid
        for method in ["COPY", "MOVE"] {
            for destination in [
                "/dav",
                "/dav/cal",
                "/dav/card",
                "/dav/file",
                "/dav/pal",
                hierarchy_root.as_str(),
            ] {
                client
                    .request_with_headers(
                        method,
                        &hierarchy_root,
                        [("destination", destination)],
                        "",
                    )
                    .await
                    .with_status(StatusCode::BAD_GATEWAY);
            }
        }

        // Test 1: Rename container
        let new_hierarchy_root = format!("{user_base_path}/Test_Folder/");
        client
            .request_with_headers(
                "MOVE",
                &hierarchy_root,
                [("destination", new_hierarchy_root.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        replace_prefix(&mut hierarchy, &hierarchy_root, &new_hierarchy_root);
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;
        // Validate changes
        let changes = client
            .sync_collection(
                &user_base_path,
                sync_token,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await
            .with_href_count(2)
            .into_propfind_response(None);
        changes
            .properties(&hierarchy_root)
            .with_status(StatusCode::NOT_FOUND);
        changes
            .properties(&new_hierarchy_root)
            .with_status(StatusCode::OK);
        let hierarchy_root = new_hierarchy_root;

        // Test 2: Copy container
        let new_hierarchy_root = format!("{user_base_path}/Test_Folder_Copy/");
        client
            .request_with_headers(
                "COPY",
                &hierarchy_root,
                [("destination", new_hierarchy_root.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        let mut copied_hierarchy = hierarchy.clone();
        replace_prefix(&mut copied_hierarchy, &hierarchy_root, &new_hierarchy_root);
        copied_hierarchy.extend_from_slice(&hierarchy);
        assert_result(&response, &copied_hierarchy);
        client.validate_values(&copied_hierarchy).await;

        // Test 3: Delete original container
        client
            .request("DELETE", &new_hierarchy_root, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;

        // Test 4: Create a shallow container and overwrite the previous one using MOVE
        let (new_hierarchy_root, mut hierarchy) =
            client.create_hierarchy(&user_base_path, 0, 0, 3).await;
        let sync_token = client
            .sync_collection(
                &user_base_path,
                sync_token,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await
            .sync_token()
            .to_string();
        client
            .request_with_headers(
                "MOVE",
                &new_hierarchy_root,
                [("destination", hierarchy_root.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::NO_CONTENT);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        replace_prefix(&mut hierarchy, &new_hierarchy_root, &hierarchy_root);
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;
        // Validate changes
        let changes = client
            .sync_collection(
                &user_base_path,
                &sync_token,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await
            .into_propfind_response(None);
        changes
            .properties(&new_hierarchy_root)
            .with_status(StatusCode::NOT_FOUND);
        changes
            .properties(&hierarchy_root)
            .with_status(StatusCode::OK);

        // Test 5: Create a deep container and overwrite the previous one using COPY
        let (new_hierarchy_root, new_hierarchy) = client
            .create_hierarchy(&user_base_path, default_test_depth, 1, 2)
            .await;
        client
            .request_with_headers(
                "COPY",
                &new_hierarchy_root,
                [("destination", hierarchy_root.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::NO_CONTENT);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        let mut orig_hierarchy = new_hierarchy.clone();
        replace_prefix(&mut orig_hierarchy, &new_hierarchy_root, &hierarchy_root);
        let mut full_hierarchy = new_hierarchy.clone();
        full_hierarchy.extend_from_slice(&orig_hierarchy);
        assert_result(&response, &full_hierarchy);
        client.validate_values(&full_hierarchy).await;

        // Test 6: Copy and move containers to a shared account
        let shared_hierarchy_root_1 = format!("{group_base_path}/Test_Shared_Folder_1/");
        let shared_hierarchy_root_2 = format!("{group_base_path}/Test_Shared_Folder_2/");
        client
            .request_with_headers(
                "MOVE",
                &new_hierarchy_root,
                [("destination", shared_hierarchy_root_1.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        client
            .request_with_headers(
                "COPY",
                &hierarchy_root,
                [("destination", shared_hierarchy_root_2.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &orig_hierarchy);
        client.validate_values(&orig_hierarchy).await;
        let response = client
            .sync_collection(&group_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        replace_prefix(
            &mut full_hierarchy,
            &new_hierarchy_root,
            &shared_hierarchy_root_1,
        );
        replace_prefix(
            &mut full_hierarchy,
            &hierarchy_root,
            &shared_hierarchy_root_2,
        );
        assert_result(&response, &full_hierarchy);
        client.validate_values(&full_hierarchy).await;

        // Delete all containers
        for shared_container in [
            shared_hierarchy_root_1,
            shared_hierarchy_root_2,
            hierarchy_root,
        ] {
            client
                .request("DELETE", &shared_container, "")
                .await
                .with_status(StatusCode::NO_CONTENT);
        }

        // Create test containers
        let mut hierarchy = vec![];
        for folder_name in ["folder1", "folder2", "folder3"] {
            let folder_path = format!("{user_base_path}/{folder_name}/");

            client
                .mkcol("MKCOL", &folder_path, [], [])
                .await
                .with_status(StatusCode::CREATED);

            for file_name in ["file1", "file2", "file3"] {
                let file_path = format!("{folder_path}{file_name}");
                let file_contents = resource_type.generate();
                client
                    .request("PUT", &file_path, &file_contents)
                    .await
                    .with_status(StatusCode::CREATED);
                hierarchy.push((file_path, file_contents));
            }

            hierarchy.push((folder_path, "".to_string()));
        }
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;

        // Test 7: Copying or moving files to the root container is not allowed
        let folder1_file1 = format!("{user_base_path}/folder1/file1");
        if resource_type != DavResourceName::File {
            for method in ["COPY", "MOVE"] {
                client
                    .request_with_headers(
                        method,
                        &folder1_file1,
                        [("destination", user_base_path.as_str())],
                        "",
                    )
                    .await
                    .with_status(StatusCode::BAD_GATEWAY);
                client
                    .request_with_headers(
                        method,
                        &folder1_file1,
                        [("destination", format!("{user_base_path}/folder2").as_str())],
                        "",
                    )
                    .await
                    .with_status(StatusCode::BAD_GATEWAY);
            }
        }

        // Test 8: Copying or moving to the same location is not allowed
        for method in ["COPY", "MOVE"] {
            client
                .request_with_headers(
                    method,
                    &folder1_file1,
                    [("destination", folder1_file1.as_str())],
                    "",
                )
                .await
                .with_status(StatusCode::BAD_GATEWAY);
        }

        // Test 9: Rename file
        let folder1_file1_new = format!("{user_base_path}/folder1/file1_new");
        client
            .request_with_headers(
                "MOVE",
                &folder1_file1,
                [("destination", folder1_file1_new.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        rename(&mut hierarchy, &folder1_file1, &folder1_file1_new);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;

        // Test 10: Move a file under a different container
        let folder2_file1_from_folder1 = format!("{user_base_path}/folder2/file1_from_folder1");
        client
            .request_with_headers(
                "MOVE",
                &folder1_file1_new,
                [("destination", folder2_file1_from_folder1.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        rename(
            &mut hierarchy,
            &folder1_file1_new,
            &folder2_file1_from_folder1,
        );
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;

        // Test 11: Move and overwrite a file under a different container
        let folder1_file2 = format!("{user_base_path}/folder1/file2");
        client
            .request_with_headers(
                "MOVE",
                &folder2_file1_from_folder1,
                [("destination", folder1_file2.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::NO_CONTENT);
        delete(&mut hierarchy, &folder1_file2);
        rename(&mut hierarchy, &folder2_file1_from_folder1, &folder1_file2);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;

        // Test 12: Copy a file under a different container
        let file3_path = format!("{user_base_path}/folder1/file3");
        let folder3_file3_from_folder1 = format!("{user_base_path}/folder3/file3_from_folder1");
        client
            .request_with_headers(
                "COPY",
                &file3_path,
                [("destination", folder3_file3_from_folder1.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        copy(&mut hierarchy, &file3_path, &folder3_file3_from_folder1);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;

        // Test 12: Copy and overwrite a file under a different container
        let folder2_file2 = format!("{user_base_path}/folder2/file2");
        client
            .request_with_headers(
                "COPY",
                &folder3_file3_from_folder1,
                [("destination", folder2_file2.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::NO_CONTENT);
        delete(&mut hierarchy, &folder2_file2);
        copy(&mut hierarchy, &folder3_file3_from_folder1, &folder2_file2);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;

        // Test 13: Copy and move files to a shared container
        let shared_hierarchy_root = format!("{group_base_path}/Test_Child_Folder/");
        let folder3_file1 = format!("{user_base_path}/folder3/file1");
        let shared_file_1 = format!("{shared_hierarchy_root}shared_file_1");
        let shared_file_2 = format!("{shared_hierarchy_root}shared_file_2");
        client
            .mkcol("MKCOL", &shared_hierarchy_root, [], [])
            .await
            .with_status(StatusCode::CREATED);
        client
            .request_with_headers(
                "MOVE",
                &folder3_file1,
                [("destination", shared_file_1.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        client
            .request_with_headers(
                "COPY",
                &folder1_file2,
                [("destination", shared_file_2.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::CREATED);
        let shared_hierarchy = vec![
            (shared_hierarchy_root.clone(), "".to_string()),
            (
                shared_file_1,
                get_contents(&hierarchy, &folder3_file1).unwrap(),
            ),
            (
                shared_file_2,
                get_contents(&hierarchy, &folder1_file2).unwrap(),
            ),
        ];
        delete(&mut hierarchy, &folder3_file1);
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &hierarchy);
        client.validate_values(&hierarchy).await;
        let response = client
            .sync_collection(&group_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_result(&response, &shared_hierarchy);
        client.validate_values(&shared_hierarchy).await;
        client
            .request("DELETE", &shared_hierarchy_root, "")
            .await
            .with_status(StatusCode::NO_CONTENT);

        if resource_type == DavResourceName::File {
            // Test 14: Move a container under a different container
            let folder2 = format!("{user_base_path}/folder2/");
            let folder3 = format!("{user_base_path}/folder3/");
            let folder2_folder3 = format!("{user_base_path}/folder2/folder3/");
            client
                .request_with_headers(
                    "MOVE",
                    &folder3,
                    [("destination", folder2_folder3.as_str())],
                    "",
                )
                .await
                .with_status(StatusCode::CREATED);
            replace_prefix(&mut hierarchy, &folder3, &folder2_folder3);
            let response = client
                .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
                .await;
            assert_result(&response, &hierarchy);
            client.validate_values(&hierarchy).await;

            // Test 15: Moving or copying a parent under a child is not allowed
            for method in ["MOVE", "COPY"] {
                client
                    .request_with_headers(
                        method,
                        &folder2_folder3,
                        [("destination", folder2.as_str())],
                        "",
                    )
                    .await
                    .with_status(StatusCode::BAD_GATEWAY);
            }

            // Test 16: Copy a container under a different container
            let folder1 = format!("{user_base_path}/folder1/");
            let folder2_folder1 = format!("{user_base_path}/folder2/folder1/");
            client
                .request_with_headers(
                    "COPY",
                    &folder1,
                    [("destination", folder2_folder1.as_str())],
                    "",
                )
                .await
                .with_status(StatusCode::CREATED);
            let response = client
                .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
                .await;
            copy_prefix(&mut hierarchy, &folder1, &folder2_folder1);
            assert_result(&response, &hierarchy);
            client.validate_values(&hierarchy).await;
        } else {
            // Test 17: UID collision
            let folder1 = format!("{user_base_path}/folder1/");
            let folder2 = format!("{user_base_path}/folder2/");
            let file_contents = resource_type.generate();
            for folder_path in [&folder1, &folder2] {
                let file_path = format!("{folder_path}uid_test");
                client
                    .request("PUT", &file_path, file_contents.as_str())
                    .await
                    .with_status(StatusCode::CREATED);
            }
            let uid_file_src = format!("{folder1}uid_test");
            let uid_file_dest = format!("{folder2}uid_test_dup");
            for method in ["COPY", "MOVE"] {
                client
                    .request_with_headers(
                        method,
                        &uid_file_src,
                        [("destination", uid_file_dest.as_str())],
                        "",
                    )
                    .await
                    .with_status(StatusCode::PRECONDITION_FAILED)
                    .with_failed_precondition(
                        if resource_type == DavResourceName::Cal {
                            "A:no-uid-conflict.D:href"
                        } else {
                            "B:no-uid-conflict.D:href"
                        },
                        &format!("{folder2}uid_test"),
                    );
            }
        }

        // Delete all containers and create a new one
        client
            .request("DELETE", &format!("{user_base_path}/folder3/"), "")
            .await
            .with_status(if resource_type == DavResourceName::File {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::NO_CONTENT
            });
        for folder in ["folder1", "folder2"] {
            let folder_path = format!("{user_base_path}/{folder}/");
            client
                .request("DELETE", &folder_path, "")
                .await
                .with_status(StatusCode::NO_CONTENT);
        }

        // Create a new test container and file
        let test_base_path = format!("{user_base_path}/My_Test_Folder/");
        client
            .mkcol("MKCOL", &test_base_path, [], [])
            .await
            .with_status(StatusCode::CREATED);
        let test_contents_1 = resource_type.generate();
        let test_contents_2 = resource_type.generate();
        let test_file1_path = format!("{test_base_path}test_file_1");
        let test_file2_path = format!("{test_base_path}test_file_2");
        let test_etag_1 = client
            .request("PUT", &test_file1_path, test_contents_1.as_str())
            .await
            .with_status(StatusCode::CREATED)
            .etag()
            .to_string();
        let test_etag_2 = client
            .request("PUT", &test_file2_path, test_contents_2.as_str())
            .await
            .with_status(StatusCode::CREATED)
            .etag()
            .to_string();

        // Test 18: Failed DAV preconditions
        for method in ["COPY", "MOVE"] {
            client
                .request_with_headers(
                    method,
                    &test_file1_path,
                    [
                        ("destination", test_file2_path.as_str()),
                        ("overwrite", "F"),
                    ],
                    "",
                )
                .await
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_empty_body();

            client
                .request_with_headers(
                    method,
                    &test_file1_path,
                    [
                        ("destination", test_file2_path.as_str()),
                        ("if-none-match", "*"),
                    ],
                    "",
                )
                .await
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_empty_body();

            let iff = format!(
                "<{test_file1_path}> (Not [{test_etag_1}]) <{test_file2_path}> (Not [{test_etag_2}])",
            );
            client
                .request_with_headers(
                    method,
                    &test_file1_path,
                    [
                        ("destination", test_file2_path.as_str()),
                        ("if", iff.as_str()),
                    ],
                    "",
                )
                .await
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_empty_body();
        }

        // Test 18: Successful DAV preconditions
        let iff =
            format!("<{test_file1_path}> ([{test_etag_1}]) <{test_file2_path}> ([{test_etag_2}])",);
        client
            .request_with_headers(
                "MOVE",
                &test_file1_path,
                [
                    ("destination", test_file2_path.as_str()),
                    ("if", iff.as_str()),
                ],
                "",
            )
            .await
            .with_status(StatusCode::NO_CONTENT);

        // Delete the test container
        client
            .request("DELETE", &test_base_path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);

        // Test 19: Quota enforcement (on CalDAV/CardDAV items are linked, not copied therefore there is no quota increase)
        if resource_type == DavResourceName::File {
            let path = format!("{}/mike/quota-test/", resource_type.base_path());
            let content = resource_type.generate();
            mike_noquota
                .mkcol("MKCOL", &path, [], [])
                .await
                .with_status(StatusCode::CREATED);
            mike_noquota
                .request_with_headers("PUT", &format!("{path}file"), [], &content)
                .await
                .with_status(StatusCode::CREATED);
            let mut num_success = 0;
            let mut did_fail = false;

            for i in 0..100 {
                let response = mike_noquota
                    .request_with_headers(
                        "COPY",
                        &path,
                        [(
                            "destination",
                            format!("{}/mike/quota-test{i}", resource_type.base_path()).as_str(),
                        )],
                        &content,
                    )
                    .await;
                match response.status {
                    StatusCode::CREATED => {
                        num_success += 1;
                    }
                    StatusCode::PRECONDITION_FAILED => {
                        did_fail = true;
                        break;
                    }
                    _ => panic!("Unexpected status code: {:?}", response.status),
                }
            }
            if !did_fail {
                panic!("Quota test failed: {} files created", num_success);
            }
            if num_success == 0 {
                panic!("Quota test failed: no files created");
            }

            mike_noquota
                .request("DELETE", &path, "")
                .await
                .with_status(StatusCode::NO_CONTENT);
            for i in 0..num_success {
                mike_noquota
                    .request(
                        "DELETE",
                        &format!("{}/mike/quota-test{i}", resource_type.base_path()),
                        "",
                    )
                    .await
                    .with_status(StatusCode::NO_CONTENT);
            }
        }
    }

    client.delete_default_containers().await;
    client.delete_default_containers_by_account("support").await;
    mike_noquota.delete_default_containers().await;
    test.assert_is_empty().await;
}

fn assert_result(response: &DavResponse, hierarchy: &[(String, String)]) {
    assert!(!hierarchy.is_empty());
    let response = response
        .hrefs()
        .into_iter()
        .filter(|h| {
            !h.ends_with("/jane/") && !h.ends_with("/support/") && !h.ends_with("/default/")
        })
        .collect::<AHashSet<_>>();
    let hierarchy = hierarchy
        .iter()
        .map(|x| x.0.as_str())
        .collect::<AHashSet<_>>();

    if hierarchy != response {
        println!("\nMissing: {:?}", hierarchy.difference(&response));
        println!("\nExtra: {:?}", response.difference(&hierarchy));

        panic!(
            "Hierarchy mismatch: expected {} items, received {} items",
            hierarchy.len(),
            response.len()
        );
    }
}

fn replace_prefix(items: &mut [(String, String)], old_prefix: &str, new_prefix: &str) {
    let mut did_replace = false;
    for (href, _) in items.iter_mut() {
        if let Some(value) = href.strip_prefix(old_prefix) {
            *href = format!("{new_prefix}{value}");
            did_replace = true;
        }
    }
    if !did_replace {
        panic!("Prefix not found: {}", old_prefix);
    }
}

fn rename(items: &mut [(String, String)], old_name: &str, new_name: &str) {
    for (href, _) in items.iter_mut() {
        if href == old_name {
            *href = new_name.to_string();
            return;
        }
    }
    panic!("Item not found: {}", old_name);
}

fn delete(items: &mut Vec<(String, String)>, name: &str) {
    let mut did_delete = false;
    items.retain(|(href, _)| {
        did_delete = did_delete || href == name;
        href != name
    });

    if !did_delete {
        panic!("Item not found: {}", name);
    }
}

fn copy(items: &mut Vec<(String, String)>, old_name: &str, new_name: &str) {
    for (href, contents) in items.iter_mut() {
        if href == old_name {
            let value = (new_name.to_string(), contents.to_string());
            items.push(value);
            return;
        }
    }
    panic!("Item not found: {}", old_name);
}

fn copy_prefix(items: &mut Vec<(String, String)>, old_prefix: &str, new_prefix: &str) {
    let mut new_items = vec![];
    for (href, contents) in items.iter() {
        if let Some(value) = href.strip_prefix(old_prefix) {
            new_items.push((format!("{new_prefix}{value}"), contents.to_string()));
        }
    }
    if !new_items.is_empty() {
        items.extend(new_items);
    } else {
        panic!("Prefix not found: {}", old_prefix);
    }
}

fn get_contents(items: &[(String, String)], name: &str) -> Option<String> {
    for (href, contents) in items.iter() {
        if href == name {
            return Some(contents.to_string());
        }
    }
    None
}
