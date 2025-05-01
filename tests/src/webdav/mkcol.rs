/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::StatusCode;

use crate::webdav::{TEST_FILE_1, TEST_ICAL_1, TEST_VCARD_1, TEST_VTIMEZONE_1};

use super::WebDavTest;

pub async fn test(test: &WebDavTest) {
    println!("Running MKCOL tests...");
    let client = test.client("john");

    // Creating collections in root elements is not allowed
    for path in [
        "/dav/file/test",
        "/dav/card/test",
        "/dav/cal/test",
        "/dav/test",
    ] {
        client
            .request("MKCOL", path, "")
            .await
            .with_status(StatusCode::NOT_FOUND);
    }

    // Create collections using MKCOL (empty body)
    for path in [
        "/dav/file/john/my-files",
        "/dav/card/john/my-cards",
        "/dav/cal/john/my-events",
    ] {
        client
            .request("MKCOL", path, "")
            .await
            .with_status(StatusCode::CREATED);
    }

    // Create resources under the newly created collections
    for (path, content) in [
        ("/dav/file/john/my-files/file1.txt", TEST_FILE_1),
        ("/dav/card/john/my-cards/card1.vcf", TEST_VCARD_1),
        ("/dav/cal/john/my-events/event1.ics", TEST_ICAL_1),
    ] {
        client
            .request("PUT", path, content)
            .await
            .with_status(StatusCode::CREATED);
    }

    // Creating a collection on a mapped resource should fail
    for path in [
        "/dav/file/john/my-files",
        "/dav/card/john/my-cards",
        "/dav/cal/john/my-events",
        "/dav/file/john/my-files/file1.txt",
        "/dav/card/john/my-cards/card1.vcf",
        "/dav/cal/john/my-events/event1.ics",
    ] {
        client
            .request("MKCOL", path, "")
            .await
            .with_status(StatusCode::METHOD_NOT_ALLOWED);
    }

    // Creating a sub-collections is allowed in FileDAV but in CalDAV and CardDAV
    for (path, expected_status) in [
        ("/dav/file/john/my-files/my-sub-files", StatusCode::CREATED),
        (
            "/dav/card/john/my-cards/my-sub-cards",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "/dav/cal/john/my-events/my-sub-events",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        client
            .request("MKCOL", path, "")
            .await
            .with_status(expected_status);
    }

    // Extended MKCOL with an unsupported resource types should fail
    for (path, resource_type) in [
        ("/dav/file/john/my-named-files", "B:addressbook"),
        ("/dav/card/john/my-named-cards", "A:calendar"),
        ("/dav/cal/john/my-named-events", "B:addressbook"),
    ] {
        client
            .mkcol("MKCOL", path, ["D:collection", resource_type], [])
            .await
            .with_status(StatusCode::FORBIDDEN)
            .match_one(
                "D:mkcol-response.D:propstat.D:error.D:valid-resourcetype",
                "",
            )
            .match_one("D:mkcol-response.D:propstat.D:prop.D:resourcetype", "");
    }

    // Create using extended MKCOL
    for (path, properties, resource_types) in [
        (
            "/dav/file/john/my-named-files/",
            [("D:displayname", "Named Files")].as_slice(),
            ["D:collection"].as_slice(),
        ),
        (
            "/dav/card/john/my-named-cards/",
            [
                ("D:displayname", "Named Cards"),
                ("B:addressbook-description", "Some amazing contacts"),
            ]
            .as_slice(),
            ["D:collection", "B:addressbook"].as_slice(),
        ),
        (
            "/dav/cal/john/my-named-events/",
            [
                ("D:displayname", "Named Events"),
                ("A:calendar-description", "Some amazing events"),
                (
                    "A:calendar-timezone",
                    &TEST_VTIMEZONE_1.replace("\n", "\r\n"),
                ),
            ]
            .as_slice(),
            ["D:collection", "A:calendar"].as_slice(),
        ),
    ] {
        let mut response = client
            .mkcol(
                "MKCOL",
                path,
                resource_types.iter().copied(),
                properties.iter().copied(),
            )
            .await
            .with_status(StatusCode::CREATED)
            .match_many("D:mkcol-response.D:propstat.D:status", ["HTTP/1.1 200 OK"]);
        for (property, _) in properties {
            response = response.match_one(
                &format!("D:mkcol-response.D:propstat.D:prop.{property}"),
                "",
            );
        }

        // Check the properties of the created collection
        let mut response = client
            .propfind(path, properties.iter().map(|x| x.0))
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .match_one("D:multistatus.D:response.D:href", path)
            .match_one(
                "D:multistatus.D:response.D:propstat.D:status",
                "HTTP/1.1 200 OK",
            );
        for (property, value) in properties {
            response = response.match_one(
                &format!("D:multistatus.D:response.D:propstat.D:prop.{property}"),
                value,
            );
        }
    }

    // Test MKCALENDAR
    client
        .mkcol(
            "MKCALENDAR",
            "/dav/cal/john/my-named-events2",
            [],
            [("D:displayname", "Named Events 2")],
        )
        .await
        .with_status(StatusCode::CREATED)
        .match_one("A:mkcalendar-response.D:propstat.D:prop.D:displayname", "")
        .match_many(
            "A:mkcalendar-response.D:propstat.D:status",
            ["HTTP/1.1 200 OK"],
        );

    // Delete everything
    for path in [
        "/dav/file/john/my-files",
        "/dav/card/john/my-cards",
        "/dav/cal/john/my-events",
        "/dav/file/john/my-named-files",
        "/dav/card/john/my-named-cards",
        "/dav/cal/john/my-named-events",
        "/dav/cal/john/my-named-events2",
    ] {
        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    client.delete_default_containers().await;
    test.assert_is_empty().await;
}
