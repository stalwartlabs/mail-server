/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::WebDavTest;

pub async fn test(test: &WebDavTest) {
    println!("Running basic tests...");
    let client = test.client("john");

    // Test OPTIONS request
    client
        .request("OPTIONS", "/dav/file", "")
        .await
        .with_header(
            "dav",
            "1, 2, 3, access-control, extended-mkcol, calendar-access, addressbook",
        )
        .with_header(
            "allow",
            concat!(
                "OPTIONS, GET, HEAD, POST, PUT, DELETE, COPY, MOVE, ",
                "MKCALENDAR, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, REPORT, ACL"
            ),
        );

    // Test Discovery
    client
        .request("PROPFIND", "/.well-known/carddav", "")
        .await
        .with_values(
            "D:multistatus.D:response.D:href",
            ["/dav/card/", "/dav/card/john/"],
        );
    test.client("jane")
        .request("PROPFIND", "/.well-known/caldav", "")
        .await
        .with_values(
            "D:multistatus.D:response.D:href",
            ["/dav/cal/", "/dav/cal/jane/", "/dav/cal/support/"],
        );
}
