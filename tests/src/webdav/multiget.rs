/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::WebDavTest;
use crate::webdav::GenerateTestDavResource;
use dav_proto::schema::property::{CalDavProperty, CardDavProperty, DavProperty, WebDavProperty};
use groupware::DavResourceName;
use hyper::StatusCode;

const MULTIGET_CALENDAR: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop>
       <D:getetag/>
       <C:calendar-data/>
     </D:prop>
     <D:href>$PATH_1</D:href>
     <D:href>$PATH_2</D:href>
   </C:calendar-multiget>
"#;
const MULTIGET_ADDRESSBOOK: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:addressbook-multiget xmlns:D="DAV:"
                        xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:prop>
       <D:getetag/>
       <C:address-data/>
     </D:prop>
     <D:href>$PATH_1</D:href>
     <D:href>$PATH_2</D:href>
   </C:addressbook-multiget>
"#;

pub async fn test(test: &WebDavTest) {
    let client = test.client("john");

    for resource_type in [DavResourceName::Cal, DavResourceName::Card] {
        println!(
            "Running REPORT multiget tests ({})...",
            resource_type.base_path()
        );

        let mut paths = Vec::new();
        for name in ["file1", "file2"] {
            let contents = resource_type.generate();
            let path = format!("{}/john/default/{}", resource_type.base_path(), name);
            let etag = client
                .request("PUT", &path, contents.as_str())
                .await
                .with_status(StatusCode::CREATED)
                .etag()
                .to_string();
            paths.push((path, etag, contents));
        }

        if resource_type == DavResourceName::Cal {
            let path = format!("{}/john", resource_type.base_path());
            let body = MULTIGET_CALENDAR
                .replace("$PATH_1", &paths[0].0)
                .replace("$PATH_2", &paths[1].0);
            let response = client
                .request("REPORT", &path, &body)
                .await
                .with_status(StatusCode::MULTI_STATUS)
                .into_propfind_response(None);
            for (path, etag, contents) in paths {
                let props = response.properties(&path);
                props
                    .get(DavProperty::WebDav(WebDavProperty::GetETag))
                    .with_values([etag.as_str()]);
                props
                    .get(DavProperty::CalDav(CalDavProperty::CalendarData(
                        Default::default(),
                    )))
                    .with_values([contents.as_str()]);
            }
        } else {
            let path = format!("{}/john", resource_type.base_path());
            let body = MULTIGET_ADDRESSBOOK
                .replace("$PATH_1", &paths[0].0)
                .replace("$PATH_2", &paths[1].0);
            let response = client
                .request("REPORT", &path, &body)
                .await
                .with_status(StatusCode::MULTI_STATUS)
                .into_propfind_response(None);
            for (path, etag, contents) in paths {
                let props = response.properties(&path);
                props
                    .get(DavProperty::WebDav(WebDavProperty::GetETag))
                    .with_values([etag.as_str()]);
                props
                    .get(DavProperty::CardDav(CardDavProperty::AddressData(
                        Default::default(),
                    )))
                    .with_values([contents.as_str()]);
            }
        }
    }

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}
