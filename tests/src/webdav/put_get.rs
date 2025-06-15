/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::WebDavTest;
use crate::webdav::*;

pub async fn test(test: &WebDavTest) {
    println!("Running PUT/GET tests...");
    let client = test.client("john");

    // Simple PUT
    let mut files = AHashMap::new();
    for (path, ct, content) in [
        ("/dav/file/john/file1.txt", "text/plain", TEST_FILE_1),
        ("/dav/file/john/file2.txt", "text/x-other", TEST_FILE_2),
        (
            "/dav/card/john/default/card1.vcf",
            "text/vcard; charset=utf-8",
            TEST_VCARD_1,
        ),
        (
            "/dav/card/john/default/card2.vcf",
            "text/vcard; charset=utf-8",
            TEST_VCARD_2,
        ),
        (
            "/dav/cal/john/default/event1.ics",
            "text/calendar; charset=utf-8",
            TEST_ICAL_1,
        ),
        (
            "/dav/cal/john/default/event2.ics",
            "text/calendar; charset=utf-8",
            TEST_ICAL_2,
        ),
    ] {
        let content = content.replace("\n", "\r\n");
        let etag = client
            .request_with_headers("PUT", path, [("content-type", ct)], &content)
            .await
            .with_status(StatusCode::CREATED)
            .etag()
            .to_string();
        files.insert(path, (content, ct, etag));
    }

    // Test GET
    for (path, (content, ct, etag)) in &files {
        client
            .request("GET", path, "")
            .await
            .with_status(StatusCode::OK)
            .with_header("etag", etag)
            .with_header("content-type", ct)
            .with_body(content);
    }

    // PUT under a non-existing parent should fail
    for (path, contents) in [
        ("/dav/file/john/foo/file1.txt", TEST_FILE_1),
        ("/dav/card/john/foo/card1.vcf", TEST_VCARD_1),
        ("/dav/cal/john/foo/event1.ics", TEST_ICAL_1),
    ] {
        client
            .request("PUT", path, contents)
            .await
            .with_status(StatusCode::CONFLICT);
    }

    // PUT under resources should fail
    for (path, contents) in [
        ("/dav/file/john/file1.txt/other-file.txt", TEST_FILE_1),
        (
            "/dav/card/john/default/card1.vcf/other-file.vcf",
            TEST_VCARD_1,
        ),
        (
            "/dav/cal/john/default/event1.ics/other-file.ical",
            TEST_ICAL_1,
        ),
    ] {
        client
            .request("PUT", path, contents)
            .await
            .with_status(StatusCode::METHOD_NOT_ALLOWED);
    }

    // PUT a non-vCard/iCalendar file should fail
    for (path, ct, content, precondition) in [
        (
            "/dav/card/john/card3.vcf",
            "text/vcard; charset=utf-8",
            TEST_FILE_1,
            "B:supported-address-data",
        ),
        (
            "/dav/cal/john/event3.ics",
            "text/calendar; charset=utf-8",
            TEST_FILE_2,
            "A:supported-calendar-data",
        ),
    ] {
        client
            .request_with_headers("PUT", path, [("content-type", ct)], content)
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_failed_precondition(precondition, "");
    }

    // Exceeding the configured file limits should fail
    let conf = &test.server.core.groupware;
    for (path, contents, max_size, expect) in [
        (
            "/dav/file/john/chunky-file1.txt",
            TEST_FILE_1,
            conf.max_file_size,
            None,
        ),
        (
            "/dav/card/john/chunky-card1.vcf",
            TEST_VCARD_1,
            conf.max_vcard_size,
            Some("B:max-resource-size"),
        ),
        (
            "/dav/cal/john/chunky-event1.ics",
            TEST_ICAL_1,
            conf.max_ical_size,
            Some("A:max-resource-size"),
        ),
    ] {
        let mut chunky_contents = String::with_capacity(max_size + contents.len());
        while chunky_contents.len() < max_size {
            chunky_contents.push_str(contents);
        }
        let response = client
            .request("PUT", path, chunky_contents)
            .await
            .with_status(
                expect
                    .map(|_| StatusCode::PRECONDITION_FAILED)
                    .unwrap_or(StatusCode::PAYLOAD_TOO_LARGE),
            );
        if let Some(expect) = expect {
            response.with_failed_precondition(expect, &max_size.to_string());
        }
    }

    // PUT requests cannot exceed quota
    let mike_noquota = test.client("mike");
    for resource_type in [
        DavResourceName::File,
        DavResourceName::Card,
        DavResourceName::Cal,
    ] {
        let path = format!("{}/mike/quota-test/", resource_type.base_path());
        mike_noquota
            .mkcol("MKCOL", &path, [], [])
            .await
            .with_status(StatusCode::CREATED);
        let mut num_success = 0;
        let mut did_fail = false;

        for i in 0..100 {
            let content = resource_type.generate();
            let available = mike_noquota.available_quota(&path).await;

            let response = mike_noquota
                .request_with_headers("PUT", &format!("{path}file{i}"), [], &content)
                .await;
            if available > content.len() as u64 {
                num_success += 1;
                response.with_status(StatusCode::CREATED);
            } else {
                response
                    .with_status(StatusCode::PRECONDITION_FAILED)
                    .with_failed_precondition("D:quota-not-exceeded", "");
                did_fail = true;
                break;
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
    }

    // PUT precondition enforcement
    let modseq = [
        test.resources("john", Collection::FileNode)
            .await
            .highest_change_id,
        test.resources("john", Collection::Calendar)
            .await
            .highest_change_id,
        test.resources("john", Collection::AddressBook)
            .await
            .highest_change_id,
    ];
    for (path, ct, content) in [
        ("/dav/file/john/file1.txt", "text/plain", TEST_FILE_1),
        (
            "/dav/card/john/default/card1.vcf",
            "text/vcard; charset=utf-8",
            TEST_VCARD_1,
        ),
        (
            "/dav/cal/john/default/event1.ics",
            "text/calendar; charset=utf-8",
            TEST_ICAL_1,
        ),
    ] {
        let content = content.replace("\n", "\r\n");
        client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", ct), ("if-none-match", "*")],
                &content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", ct), ("overwrite", "F")],
                &content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", ct), ("if", "([\"3827\"])")],
                &content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        client
            .request_with_headers(
                "PUT",
                path,
                [
                    ("content-type", ct),
                    ("if", "([\"3827\"])"),
                    ("prefer", "return=representation"),
                ],
                &content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_header("preference-applied", "return=representation")
            .with_body(&content);
    }
    assert_eq!(
        [
            test.resources("john", Collection::FileNode)
                .await
                .highest_change_id,
            test.resources("john", Collection::Calendar)
                .await
                .highest_change_id,
            test.resources("john", Collection::AddressBook)
                .await
                .highest_change_id,
        ],
        modseq
    );

    // Update files using etags
    for (path, (content, ct, etag)) in &mut files {
        let condition = format!("([{}])", etag);
        *content = content.replace("X-TEST:SEQ1", "X-TEST:SEQ2");
        *etag = client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", &**ct), ("if", condition.as_str())],
                content.as_str(),
            )
            .await
            .with_status(StatusCode::NO_CONTENT)
            .etag()
            .to_string();
    }

    // Test GET
    for (path, (content, ct, etag)) in &files {
        client
            .request("GET", path, "")
            .await
            .with_status(StatusCode::OK)
            .with_header("etag", etag)
            .with_header("content-type", ct)
            .with_body(content);
    }

    // PUT requests require unique UIDs
    for (path, ct, content, precond_key, precond_value) in [
        (
            "/dav/card/john/default/card5.vcf",
            "text/vcard; charset=utf-8",
            TEST_VCARD_1,
            "B:no-uid-conflict.D:href",
            "/dav/card/john/default/card1.vcf",
        ),
        (
            "/dav/cal/john/default/event5.ics",
            "text/calendar; charset=utf-8",
            TEST_ICAL_1,
            "A:no-uid-conflict.D:href",
            "/dav/cal/john/default/event1.ics",
        ),
    ] {
        client
            .request_with_headers(
                "PUT",
                path,
                [("content-type", ct), ("if-none-match", "*")],
                content,
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_failed_precondition(precond_key, precond_value);
    }

    // iCal containing different component types should fail
    client
        .request_with_headers(
            "PUT",
            "/dav/cal/john/default/invalid.ics",
            [
                ("content-type", "text/calendar; charset=utf-8"),
                ("if-none-match", "*"),
            ],
            r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:1234567890
SUMMARY:Test Event
DTSTART;TZID=Europe/London:20231001T120000
DTEND;TZID=Europe/London:20231001T130000
END:VEVENT
BEGIN:VTODO
UID:1234567890
SUMMARY:Test Task
DTSTART;TZID=Europe/London:20231001T120000
DTEND;TZID=Europe/London:20231001T130000
END:VTODO
END:VCALENDAR
"#,
        )
        .await
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_failed_precondition("A:valid-calendar-object-resource", "");

    // iCal referencing more than one UID should fail
    client
        .request_with_headers(
            "PUT",
            "/dav/cal/john/default/invalid.ics",
            [
                ("content-type", "text/calendar; charset=utf-8"),
                ("if-none-match", "*"),
            ],
            r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:1234567890
SUMMARY:Test Event 1
DTSTART;TZID=Europe/London:20231001T120000
DTEND;TZID=Europe/London:20231001T130000
END:VEVENT
BEGIN:VEVENT
UID:1234567891
SUMMARY:Test Event 2
DTSTART;TZID=Europe/London:20231001T120000
DTEND;TZID=Europe/London:20231001T130000
END:VEVENT
END:VCALENDAR
"#,
        )
        .await
        .with_status(StatusCode::PRECONDITION_FAILED)
        .with_failed_precondition("A:valid-calendar-object-resource", "");

    // Deleting unknown/invalid destinations should fail
    for (path, expect) in [
        ("/dav/file/john/unknown.txt", StatusCode::NOT_FOUND),
        ("/dav/card/john/default/unknown.txt", StatusCode::NOT_FOUND),
        ("/dav/cal/john/default/unknown.txt", StatusCode::NOT_FOUND),
        ("/dav/file/john", StatusCode::FORBIDDEN),
        ("/dav/cal/john", StatusCode::FORBIDDEN),
        ("/dav/card/john", StatusCode::FORBIDDEN),
        ("/dav/pal/john", StatusCode::METHOD_NOT_ALLOWED),
        ("/dav/file", StatusCode::FORBIDDEN),
        ("/dav/cal", StatusCode::FORBIDDEN),
        ("/dav/card", StatusCode::FORBIDDEN),
        ("/dav/pal", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        client.request("DELETE", path, "").await.with_status(expect);
    }

    // Delete files
    for (path, (_, _, etag)) in &files {
        client
            .request_with_headers("DELETE", path, [("if", "([\"3827\"])")], "")
            .await
            .with_status(StatusCode::PRECONDITION_FAILED);

        let condition = format!("([{}])", etag);
        client
            .request_with_headers("DELETE", path, [("if", condition.as_str())], "")
            .await
            .with_status(StatusCode::NO_CONTENT);

        client
            .request("DELETE", path, "")
            .await
            .with_status(StatusCode::NOT_FOUND);
    }

    client.delete_default_containers().await;
    mike_noquota.delete_default_containers().await;
    test.assert_is_empty().await;
}
