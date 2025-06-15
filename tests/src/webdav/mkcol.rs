/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::StatusCode;

use crate::webdav::{TEST_FILE_1, TEST_ICAL_1, TEST_VCARD_1, TEST_VTIMEZONE_1};

use super::{DavResponse, DummyWebDavClient, WebDavTest};

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
            .with_value(
                "D:mkcol-response.D:propstat.D:error.D:valid-resourcetype",
                "",
            )
            .with_value("D:mkcol-response.D:propstat.D:prop.D:resourcetype", "");
    }

    // Create using extended MKCOL
    for (path, expected_properties, resource_types) in [
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
        let response = client
            .mkcol(
                "MKCOL",
                path,
                resource_types.iter().copied(),
                expected_properties.iter().copied(),
            )
            .await
            .with_status(StatusCode::CREATED)
            .into_propfind_response("D:mkcol-response".into());
        let properties = response.properties("");
        for (property, _) in expected_properties {
            properties
                .get(property)
                .with_status(StatusCode::OK)
                .with_values([""]);
        }

        // Check the properties of the created collection
        let response = client
            .propfind(path, expected_properties.iter().map(|x| x.0))
            .await;
        let properties = response.properties(path);
        for (property, value) in expected_properties {
            properties
                .get(property)
                .with_status(StatusCode::OK)
                .with_values([*value]);
        }
    }

    // Test MKCALENDAR
    client
        .mkcol(
            "MKCALENDAR",
            "/dav/cal/john/my-named-events2",
            [],
            [
                ("D:displayname", "Named Events 2"),
                ("A:calendar-description", ""),
                ("A:supported-calendar-component-set", ""),
            ],
        )
        .await
        .with_status(StatusCode::CREATED)
        .with_value("A:mkcalendar-response.D:propstat.D:prop.D:displayname", "")
        .with_values(
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

impl DummyWebDavClient {
    pub async fn mkcol(
        &self,
        method: &str,
        path: &str,
        resource_types: impl IntoIterator<Item = &str>,
        properties: impl IntoIterator<Item = (&str, &str)>,
    ) -> DavResponse {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:mkcol xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" xmlns:B=\"urn:ietf:params:xml:ns:carddav\">",
            "<D:set><D:prop>"
        )
        .to_string();

        let mut has_resource_type = false;
        for (idx, resource_type) in resource_types.into_iter().enumerate() {
            if idx == 0 {
                request.push_str("<D:resourcetype>");
            }
            request.push_str(&format!("<{resource_type}/>"));
            has_resource_type = true;
        }

        if has_resource_type {
            request.push_str("</D:resourcetype>");
        }

        for (key, value) in properties {
            request.push_str(&format!("<{key}>{value}</{key}>"));
        }
        request.push_str("</D:prop></D:set></D:mkcol>");

        if method == "MKCALENDAR" {
            request = request.replace("D:mkcol", "A:mkcalendar");
        }

        self.request(method, path, &request).await
    }
}
