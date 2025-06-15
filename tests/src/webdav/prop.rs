/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavResponse, DummyWebDavClient, WebDavTest};
use crate::webdav::{GenerateTestDavResource, TEST_ICAL_2, TEST_VTIMEZONE_1};
use ahash::{AHashMap, AHashSet};
use dav_proto::schema::{
    property::{CalDavProperty, CardDavProperty, DavProperty, PrincipalProperty, WebDavProperty},
    request::DeadElementTag,
};
use groupware::DavResourceName;
use hyper::StatusCode;

pub async fn test(test: &WebDavTest) {
    let client = test.client("jane");

    for resource_type in [
        DavResourceName::File,
        DavResourceName::Cal,
        DavResourceName::Card,
    ] {
        println!(
            "Running PROPFIND/PROPPATCH tests ({})...",
            resource_type.base_path()
        );
        let user_base_path = format!("{}/jane", resource_type.base_path());
        let group_base_path = format!("{}/support", resource_type.base_path());

        // Create a new test container and file
        let test_base_path = format!("{user_base_path}/PropFind_Folder/");
        let etag_folder = client
            .mkcol("MKCOL", &test_base_path, [], [])
            .await
            .with_status(StatusCode::CREATED)
            .etag()
            .to_string();
        let test_contents = resource_type.generate();
        let test_path = format!("{test_base_path}test_file");
        let etag_file = client
            .request_with_headers(
                "PUT",
                &test_path,
                [("content-type", "text/x-other")],
                test_contents.as_str(),
            )
            .await
            .with_status(StatusCode::CREATED)
            .etag()
            .to_string();

        // Test 1: PROPFIND Depth 0 on root
        client
            .request_with_headers("PROPFIND", resource_type.base_path(), [("depth", "0")], "")
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs([resource_type.collection_path()]);

        // Test 2: PROPFIND Depth 0 on user base path
        client
            .request_with_headers("PROPFIND", &user_base_path, [("depth", "0")], "")
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs([format!("{user_base_path}/").as_str()]);

        // Test 3: PROPFIND Depth 1 on root
        client
            .request_with_headers("PROPFIND", resource_type.base_path(), [("depth", "1")], "")
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs([
                resource_type.collection_path(),
                format!("{user_base_path}/").as_str(),
                format!("{group_base_path}/").as_str(),
            ]);

        // Test 4: Infinity depth is not allowed
        for path in [resource_type.base_path(), user_base_path.as_str()] {
            client
                .request_with_headers("PROPFIND", path, [("depth", "infinity")], "")
                .await
                .with_status(StatusCode::FORBIDDEN);
        }

        // Test 5: PROPFIND Depth 1 on user base path
        client
            .request_with_headers("PROPFIND", &user_base_path, [("depth", "1")], "")
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(
                [
                    format!("{user_base_path}/default/").as_str(),
                    format!("{user_base_path}/").as_str(),
                    &test_base_path,
                ]
                .into_iter()
                .skip(if resource_type == DavResourceName::File {
                    1
                } else {
                    0
                }),
            );

        // Test 6: PROPFIND Depth 1 on created collection
        client
            .request_with_headers("PROPFIND", &test_base_path, [("depth", "1")], "")
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs([test_base_path.as_str(), test_path.as_str()]);

        // Test 7: Infinity depth is not allowed on file containers
        client
            .request_with_headers("PROPFIND", &test_base_path, [("depth", "infinity")], "")
            .await
            .with_status(if resource_type == DavResourceName::File {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::MULTI_STATUS
            });

        // Test 8 PROPFIND with depth-no-root
        client
            .request_with_headers(
                "PROPFIND",
                &user_base_path,
                [("depth", "1"), ("prefer", "depth-noroot")],
                "",
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs(
                [
                    format!("{user_base_path}/default/").as_str(),
                    &test_base_path,
                ]
                .into_iter()
                .skip(if resource_type == DavResourceName::File {
                    1
                } else {
                    0
                }),
            );
        client
            .request_with_headers(
                "PROPFIND",
                &test_base_path,
                [("depth", "1"), ("prefer", "depth-noroot")],
                "",
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .with_hrefs([test_path.as_str()]);

        // Test 8 PROPFIND with prefer return=minimal
        let response = client
            .propfind_with_headers(&test_base_path, ALL_DAV_PROPERTIES, [])
            .await;
        response
            .properties(&test_base_path)
            .is_defined(DavProperty::WebDav(WebDavProperty::GetETag))
            .is_defined(DavProperty::Principal(PrincipalProperty::GroupMembership));
        let response = client
            .propfind_with_headers(
                &test_base_path,
                ALL_DAV_PROPERTIES,
                [("prefer", "return=minimal")],
            )
            .await;
        response
            .properties(&test_base_path)
            .is_defined(DavProperty::WebDav(WebDavProperty::GetETag))
            .is_undefined(DavProperty::Principal(PrincipalProperty::GroupMembership));

        // Test 9: Retrieve all static properties
        for (path, etag, is_file) in [
            (&test_base_path, &etag_folder, false),
            (&test_path, &etag_file, true),
        ] {
            let response = client.propfind(path, ALL_DAV_PROPERTIES).await;
            let properties = response.properties(path);
            properties
                .get(DavProperty::WebDav(WebDavProperty::CreationDate))
                .is_not_empty();
            properties
                .get(DavProperty::WebDav(WebDavProperty::GetLastModified))
                .is_not_empty();
            properties
                .get(DavProperty::WebDav(WebDavProperty::SyncToken))
                .is_not_empty();
            properties
                .get(DavProperty::WebDav(WebDavProperty::GetETag))
                .with_values([etag.as_str()]);
            properties
                .get(DavProperty::WebDav(WebDavProperty::SupportedLock))
                .with_values([
                    "D:lockentry.D:lockscope.D:exclusive",
                    "D:lockentry.D:locktype.D:write",
                    "D:lockentry.D:lockscope.D:shared",
                    "D:lockentry.D:locktype.D:write",
                ]);
            properties
                .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal))
                .with_values([
                    format!("D:href:{}/jane/", DavResourceName::Principal.base_path()).as_str(),
                ]);
            properties
                .get(DavProperty::WebDav(WebDavProperty::Owner))
                .with_values([
                    format!("D:href:{}/jane/", DavResourceName::Principal.base_path()).as_str(),
                ]);
            properties
                .get(DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet))
                .is_not_empty();
            properties
                .get(DavProperty::WebDav(WebDavProperty::AclRestrictions))
                .with_values(["D:grant-only", "D:no-invert"]);
            properties
                .get(DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet))
                .with_values([
                    format!("D:href:{}", DavResourceName::Principal.collection_path()).as_str(),
                ]);

            if is_file {
                // File specific properties
                properties
                    .get(DavProperty::WebDav(WebDavProperty::GetContentType))
                    .with_values([match resource_type {
                        DavResourceName::File => "text/x-other",
                        DavResourceName::Cal => "text/calendar",
                        DavResourceName::Card => "text/vcard",
                        _ => unreachable!(),
                    }]);
                properties
                    .get(DavProperty::WebDav(WebDavProperty::GetContentLength))
                    .with_values([test_contents.len().to_string().as_str()]);
            } else {
                // Collection specific properties
                properties
                    .get(DavProperty::WebDav(WebDavProperty::GetCTag))
                    .is_not_empty();
                properties
                    .get(DavProperty::WebDav(WebDavProperty::ResourceType))
                    .with_values(match resource_type {
                        DavResourceName::File => ["D:collection"].as_slice().iter().copied(),
                        DavResourceName::Cal => {
                            ["D:collection", "A:calendar"].as_slice().iter().copied()
                        }
                        DavResourceName::Card => {
                            ["D:collection", "B:addressbook"].as_slice().iter().copied()
                        }
                        _ => unreachable!(),
                    });
                let used_bytes: u64 = properties
                    .get(DavProperty::WebDav(WebDavProperty::QuotaUsedBytes))
                    .value()
                    .parse()
                    .unwrap();
                let available_bytes: u64 = properties
                    .get(DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes))
                    .value()
                    .parse()
                    .unwrap();
                assert!(used_bytes > 0);
                assert!(available_bytes > 0);
                properties
                    .get(DavProperty::WebDav(WebDavProperty::SupportedReportSet))
                    .with_values(match resource_type {
                        DavResourceName::File => [
                            "D:supported-report.D:report.D:sync-collection",
                            "D:supported-report.D:report.D:acl-principal-prop-set",
                            "D:supported-report.D:report.D:principal-match",
                        ]
                        .as_slice()
                        .iter()
                        .copied(),
                        DavResourceName::Cal => [
                            "D:supported-report.D:report.A:calendar-query",
                            "D:supported-report.D:report.D:sync-collection",
                            "D:supported-report.D:report.D:acl-principal-prop-set",
                            "D:supported-report.D:report.D:expand-property",
                            "D:supported-report.D:report.A:free-busy-query",
                            "D:supported-report.D:report.A:calendar-multiget",
                            "D:supported-report.D:report.D:principal-match",
                        ]
                        .as_slice()
                        .iter()
                        .copied(),
                        DavResourceName::Card => [
                            "D:supported-report.D:report.B:addressbook-multiget",
                            "D:supported-report.D:report.D:sync-collection",
                            "D:supported-report.D:report.D:acl-principal-prop-set",
                            "D:supported-report.D:report.D:principal-match",
                            "D:supported-report.D:report.B:addressbook-query",
                            "D:supported-report.D:report.D:expand-property",
                        ]
                        .as_slice()
                        .iter()
                        .copied(),
                        _ => unreachable!(),
                    });

                if resource_type == DavResourceName::Cal {
                    properties
                        .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
                        .with_values([
                            "D:privilege.D:all",
                            "D:privilege.D:read",
                            "D:privilege.D:write",
                            "D:privilege.D:write-properties",
                            "D:privilege.D:write-content",
                            "D:privilege.D:unlock",
                            "D:privilege.D:read-acl",
                            "D:privilege.D:read-current-user-privilege-set",
                            "D:privilege.D:write-acl",
                            "D:privilege.D:bind",
                            "D:privilege.D:unbind",
                            "D:privilege.A:read-free-busy",
                        ]);
                    properties
                        .get(DavProperty::CalDav(
                            CalDavProperty::SupportedCalendarComponentSet,
                        ))
                        .with_values([
                            "A:comp.[name]:VAVAILABILITY",
                            "A:comp.[name]:AVAILABLE",
                            "A:comp.[name]:VRESOURCE",
                            "A:comp.[name]:VTODO",
                            "A:comp.[name]:DAYLIGHT",
                            "A:comp.[name]:STANDARD",
                            "A:comp.[name]:VLOCATION",
                            "A:comp.[name]:VTIMEZONE",
                            "A:comp.[name]:VFREEBUSY",
                            "A:comp.[name]:VEVENT",
                            "A:comp.[name]:VJOURNAL",
                            "A:comp.[name]:PARTICIPANT",
                            "A:comp.[name]:VALARM",
                        ]);
                    properties
                        .get(DavProperty::CalDav(CalDavProperty::SupportedCalendarData))
                        .with_values([
                            concat!("A:calendar-data-type.", "[content-type]:text/calendar"),
                            "A:calendar-data-type.[version]:2.0",
                            "A:calendar-data-type.[version]:1.0",
                        ]);
                    properties
                        .get(DavProperty::CalDav(CalDavProperty::SupportedCollationSet))
                        .with_values([
                            "A:supported-collation:i;unicode-casemap",
                            "A:supported-collation:i;ascii-casemap",
                        ]);
                    properties
                        .get(DavProperty::CalDav(CalDavProperty::MinDateTime))
                        .with_values(["0001-01-01T00:00:00Z"]);
                    properties
                        .get(DavProperty::CalDav(CalDavProperty::MaxDateTime))
                        .with_values(["9999-12-31T23:59:59Z"]);
                    for (key, value) in [
                        (
                            DavProperty::CalDav(CalDavProperty::MaxResourceSize),
                            test.server.core.groupware.max_ical_size,
                        ),
                        (
                            DavProperty::CalDav(CalDavProperty::MaxInstances),
                            test.server.core.groupware.max_ical_instances,
                        ),
                        (
                            DavProperty::CalDav(CalDavProperty::MaxAttendeesPerInstance),
                            test.server.core.groupware.max_ical_attendees_per_instance,
                        ),
                    ] {
                        properties
                            .get(key)
                            .with_values([value.to_string().as_str()]);
                    }
                } else {
                    if resource_type == DavResourceName::Card {
                        properties
                            .get(DavProperty::CardDav(CardDavProperty::SupportedAddressData))
                            .with_values([
                                concat!("B:address-data-type.", "[content-type]:text/vcard"),
                                "B:address-data-type.[version]:3.0",
                                "B:address-data-type.[version]:4.0",
                                "B:address-data-type.[version]:2.1",
                            ]);
                        properties
                            .get(DavProperty::CardDav(CardDavProperty::SupportedCollationSet))
                            .with_values([
                                "B:supported-collation:i;unicode-casemap",
                                "B:supported-collation:i;ascii-casemap",
                            ]);
                        properties
                            .get(DavProperty::CardDav(CardDavProperty::MaxResourceSize))
                            .with_values([test
                                .server
                                .core
                                .groupware
                                .max_vcard_size
                                .to_string()
                                .as_str()]);
                    }

                    properties
                        .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
                        .with_values([
                            "D:privilege.D:all",
                            "D:privilege.D:read",
                            "D:privilege.D:write",
                            "D:privilege.D:write-properties",
                            "D:privilege.D:write-content",
                            "D:privilege.D:unlock",
                            "D:privilege.D:read-acl",
                            "D:privilege.D:read-current-user-privilege-set",
                            "D:privilege.D:write-acl",
                            "D:privilege.D:bind",
                            "D:privilege.D:unbind",
                        ]);
                }
            }
        }

        // Test 10: expand-property report
        for path in [&test_base_path, &test_path] {
            let response = client
                .request("REPORT", path, EXPAND_REPORT_QUERY)
                .await
                .with_status(StatusCode::MULTI_STATUS)
                .into_propfind_response(None);
            let properties = response.properties(path);
            for prop in [
                DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
                DavProperty::WebDav(WebDavProperty::Owner),
            ] {
                properties.get(prop).with_some_values([
                    format!(
                        "D:response.D:href:{}/jane/",
                        DavResourceName::Principal.base_path(),
                    )
                    .as_str(),
                    "D:response.D:propstat.D:prop.D:displayname:Jane Doe-Smith",
                ]);
            }
        }

        for (path, etag, is_file) in [
            (&test_base_path, &etag_folder, false),
            (&test_path, &etag_file, true),
        ] {
            // Test 11: PROPPATCH should fail when a precondition fails
            client
                .proppatch(
                    path,
                    [(
                        DavProperty::WebDav(WebDavProperty::DisplayName),
                        "Magnific name",
                    )],
                    [],
                    [("if", format!("(Not [{etag}])").as_str())],
                )
                .await
                .with_status(StatusCode::PRECONDITION_FAILED);
            client
                .proppatch(
                    path,
                    [(
                        DavProperty::WebDav(WebDavProperty::DisplayName),
                        "Magnific name - second try",
                    )],
                    [],
                    [("if", format!("([{etag}])").as_str())],
                )
                .await
                .with_status(StatusCode::MULTI_STATUS);
            client
                .propfind(path, [DavProperty::WebDav(WebDavProperty::GetETag)])
                .await
                .properties(path)
                .get(DavProperty::WebDav(WebDavProperty::GetETag))
                .with_status(StatusCode::OK)
                .without_values([etag.as_str()]);

            // Test 12: PROPPATCH set on DAV properties
            client
                .patch_and_check(
                    path,
                    [
                        (
                            DavProperty::WebDav(WebDavProperty::DisplayName),
                            "New display name",
                        ),
                        (
                            DavProperty::WebDav(WebDavProperty::CreationDate),
                            "2000-01-01T00:00:00Z",
                        ),
                        (
                            DavProperty::DeadProperty(DeadElementTag::new(
                                "my-dead-element".to_string(),
                                Some("xmlns=\"http://example.com/ns/\" prop=\"abc\"".to_string()),
                            )),
                            "this is a dead but exciting element",
                        ),
                    ],
                )
                .await;
            client
                .patch_and_check(
                    path,
                    [(
                        DavProperty::DeadProperty(DeadElementTag::new(
                            "my-dead-element".to_string(),
                            Some("xmlns=\"http://example.com/ns/\" prop=\"xyz\"".to_string()),
                        )),
                        "this is a modified dead but exciting element",
                    )],
                )
                .await;

            // Test 13: PROPPATCH remove on DAV properties
            let mut props = vec![
                (
                    DavProperty::DeadProperty(DeadElementTag::new(
                        "my-dead-element".to_string(),
                        Some("xmlns=\"http://example.com/ns/\"".to_string()),
                    )),
                    "",
                ),
                (DavProperty::WebDav(WebDavProperty::DisplayName), ""),
            ];
            if !is_file && resource_type == DavResourceName::Cal {
                // DisplayName can be removed from calendar collections
                props.pop();
            }
            client.patch_and_check(path, props).await;

            match resource_type {
                DavResourceName::File if is_file => {
                    // Test 14: Change a file's content-type
                    client
                        .patch_and_check(
                            path,
                            [(
                                DavProperty::WebDav(WebDavProperty::GetContentType),
                                "text/x-yadda-yadda",
                            )],
                        )
                        .await;
                }
                DavResourceName::Cal if !is_file => {
                    // Test 15: Change a calendar's properties
                    client
                        .patch_and_check(
                            path,
                            [
                                (
                                    DavProperty::CalDav(CalDavProperty::CalendarDescription),
                                    "New calendar description",
                                ),
                                (
                                    DavProperty::CalDav(CalDavProperty::TimezoneId),
                                    "Europe/Ljubljana",
                                ),
                            ],
                        )
                        .await;
                    client
                        .patch_and_check(
                            path,
                            [
                                (DavProperty::CalDav(CalDavProperty::CalendarDescription), ""),
                                (DavProperty::CalDav(CalDavProperty::TimezoneId), ""),
                            ],
                        )
                        .await;
                    client
                        .patch_and_check(
                            path,
                            [(
                                DavProperty::CalDav(CalDavProperty::CalendarTimezone),
                                TEST_VTIMEZONE_1.replace('\n', "\r\n").as_str(),
                            )],
                        )
                        .await;
                }
                DavResourceName::Card if !is_file => {
                    // Test 16: Change an addressbook's properties
                    client
                        .patch_and_check(
                            path,
                            [(
                                DavProperty::CardDav(CardDavProperty::AddressbookDescription),
                                "New calendar description",
                            )],
                        )
                        .await;
                    client
                        .patch_and_check(
                            path,
                            [(
                                DavProperty::CardDav(CardDavProperty::AddressbookDescription),
                                "",
                            )],
                        )
                        .await;
                }
                _ => (),
            }

            // Test 17: PROPPATCH should fail on large properties
            let mut chunky_props = vec![
                DavProperty::WebDav(WebDavProperty::DisplayName),
                DavProperty::DeadProperty(DeadElementTag::new(
                    "my-chunky-dead-element".to_string(),
                    Some("xmlns=\"http://example.com/ns/\"".to_string()),
                )),
            ];
            if !is_file {
                if resource_type == DavResourceName::Cal {
                    chunky_props.push(DavProperty::CalDav(CalDavProperty::CalendarDescription));
                } else if resource_type == DavResourceName::Card {
                    chunky_props.push(DavProperty::CardDav(
                        CardDavProperty::AddressbookDescription,
                    ));
                }
            }
            let chunky_live_contents = (0..=(test.server.core.groupware.live_property_size + 1))
                .map(|_| "a")
                .collect::<String>();
            let chunky_dead_contents =
                (0..=(test.server.core.groupware.dead_property_size.unwrap() + 1))
                    .map(|_| "a")
                    .collect::<String>();
            let response = client
                .proppatch(
                    path,
                    chunky_props.iter().map(|prop| {
                        (
                            prop.clone(),
                            if matches!(prop, DavProperty::DeadProperty(_)) {
                                &chunky_dead_contents
                            } else {
                                &chunky_live_contents
                            }
                            .as_str(),
                        )
                    }),
                    [],
                    [],
                )
                .await
                .into_propfind_response(None);
            let props = response.properties(path);
            for prop in chunky_props {
                props
                    .get(prop)
                    .with_status(StatusCode::INSUFFICIENT_STORAGE)
                    .with_description("Property value is too long");
            }

            // Test 18: PROPPATCH should fail on invalid calendar property values
            if !is_file && resource_type == DavResourceName::Cal {
                let response = client
                    .proppatch(
                        path,
                        [
                            (
                                DavProperty::CalDav(CalDavProperty::TimezoneId),
                                "unknown/zone",
                            ),
                            (
                                DavProperty::CalDav(CalDavProperty::CalendarTimezone),
                                TEST_ICAL_2,
                            ),
                        ],
                        [],
                        [],
                    )
                    .await
                    .into_propfind_response(None);
                let props = response.properties(path);
                props
                    .get(DavProperty::CalDav(CalDavProperty::TimezoneId))
                    .with_status(StatusCode::PRECONDITION_FAILED)
                    .with_description("Invalid timezone ID");
                props
                    .get(DavProperty::CalDav(CalDavProperty::CalendarTimezone))
                    .with_status(StatusCode::PRECONDITION_FAILED)
                    .with_description("Invalid calendar timezone");
            }
        }

        client
            .request("DELETE", &test_base_path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    client.delete_default_containers().await;
    client.delete_default_containers_by_account("support").await;
    test.assert_is_empty().await;
}

#[derive(Debug)]
pub struct DavMultiStatus {
    pub response: DavResponse,
    pub hrefs: AHashMap<String, DavProperties>,
}

#[derive(Debug, serde::Serialize)]
pub struct DavItem {
    #[serde(serialize_with = "serialize_status_code")]
    pub status: StatusCode,
    pub values: AHashMap<String, Vec<String>>,
    pub error: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct DavProperties {
    #[serde(skip)]
    status: StatusCode,
    props: Vec<DavItem>,
}

impl DavMultiStatus {
    pub fn properties(&self, href: &str) -> DavPropertyResult<'_> {
        DavPropertyResult {
            response: &self.response,
            properties: self.hrefs.get(href).unwrap_or_else(|| {
                self.response.dump_response();
                panic!(
                    "No properties found for href: {href} in {}",
                    serde_json::to_string_pretty(&self.hrefs).unwrap()
                )
            }),
        }
    }

    pub fn with_hrefs<'x>(&self, expect_hrefs: impl IntoIterator<Item = &'x str>) -> &Self {
        let expect_hrefs: AHashSet<_> = expect_hrefs.into_iter().collect();
        let hrefs: AHashSet<_> = self.hrefs.keys().map(|s| s.as_str()).collect();
        if hrefs != expect_hrefs {
            self.response.dump_response();
            panic!("Expected hrefs {expect_hrefs:?}, but got {hrefs:?}",);
        }
        self
    }
}

pub struct DavPropertyResult<'x> {
    pub response: &'x DavResponse,
    pub properties: &'x DavProperties,
}

pub struct DavQueryResult<'x> {
    pub response: &'x DavResponse,
    pub prop: &'x DavItem,
    pub values: &'x [String],
}

impl DavPropertyResult<'_> {
    pub fn get(&self, name: impl AsRef<str>) -> DavQueryResult<'_> {
        let name = name.as_ref();
        self.properties
            .props
            .iter()
            .find_map(|prop| {
                prop.values.get(name).map(|values| DavQueryResult {
                    response: self.response,
                    prop,
                    values,
                })
            })
            .unwrap_or_else(|| {
                self.response.dump_response();
                panic!(
                    "No property found for name: {name} in {}",
                    serde_json::to_string_pretty(&self.properties.props).unwrap()
                )
            })
    }

    pub fn with_status(&self, status: StatusCode) -> &Self {
        if self.properties.status != status {
            self.response.dump_response();
            panic!(
                "Expected status {status}, but got {}",
                self.properties.status
            );
        }
        self
    }

    pub fn is_defined(&self, name: impl AsRef<str>) -> &Self {
        if self
            .properties
            .props
            .iter()
            .any(|prop| prop.values.contains_key(name.as_ref()))
        {
            self
        } else {
            self.response.dump_response();
            panic!("Expected property {} to be defined", name.as_ref());
        }
    }

    pub fn is_undefined(&self, name: impl AsRef<str>) -> &Self {
        if self
            .properties
            .props
            .iter()
            .any(|prop| prop.values.contains_key(name.as_ref()))
        {
            self.response.dump_response();
            panic!("Expected property {} to be undefined", name.as_ref());
        }
        self
    }

    pub fn calendar_data(&self) -> DavQueryResult<'_> {
        self.get(DavProperty::CalDav(CalDavProperty::CalendarData(
            Default::default(),
        )))
    }
}

impl<'x> DavQueryResult<'x> {
    pub fn with_values(&self, expected_values: impl IntoIterator<Item = &'x str>) -> &Self {
        let expected_values = AHashSet::from_iter(expected_values);
        let values = self
            .values
            .iter()
            .map(|s| s.as_str())
            .collect::<AHashSet<_>>();

        if values != expected_values {
            self.response.dump_response();
            assert_eq!(values, expected_values,);
        }
        self
    }

    pub fn with_some_values(&self, expected_values: impl IntoIterator<Item = &'x str>) -> &Self {
        let values = self
            .values
            .iter()
            .map(|s| s.as_str())
            .collect::<AHashSet<_>>();

        for expected_value in expected_values {
            if !values.contains(expected_value) {
                self.response.dump_response();
                panic!("Expected at least one of {expected_value:?} values, but got {values:?}",);
            }
        }

        self
    }

    pub fn with_any_values(&self, expected_values: impl IntoIterator<Item = &'x str>) -> &Self {
        let values = self
            .values
            .iter()
            .map(|s| s.as_str())
            .collect::<AHashSet<_>>();
        let expected_values = AHashSet::from_iter(expected_values);

        if values.is_disjoint(&expected_values) {
            self.response.dump_response();
            panic!("Expected at least one of {expected_values:?} values, but got {values:?}",);
        }

        self
    }

    pub fn without_values(&self, expected_values: impl IntoIterator<Item = &'x str>) -> &Self {
        let expected_values = AHashSet::from_iter(expected_values);
        let values = self
            .values
            .iter()
            .map(|s| s.as_str())
            .collect::<AHashSet<_>>();

        if !expected_values.is_disjoint(&values) {
            self.response.dump_response();
            panic!("Expected no {expected_values:?} values, but got {values:?}",);
        }
        self
    }

    pub fn is_not_empty(&self) -> &Self {
        if self.values.is_empty() || self.values.iter().all(|s| s.is_empty()) {
            self.response.dump_response();
            panic!("Expected non-empty values, but got {:?}", self.values);
        }
        self
    }

    pub fn value(&self) -> &str {
        if let Some(value) = self.values.iter().find(|s| !s.is_empty()) {
            value
        } else {
            self.response.dump_response();
            panic!("Expected a value, but got {:?}", self.values);
        }
    }

    pub fn with_status(&self, status: StatusCode) -> &Self {
        if self.prop.status != status {
            self.response.dump_response();
            panic!("Expected status {status}, but got {}", self.prop.status);
        }
        self
    }

    pub fn with_description(&self, description: &str) -> &Self {
        if self.prop.description.as_deref() != Some(description) {
            self.response.dump_response();
            panic!(
                "Expected description {description}, but got {:?}",
                self.prop.description
            );
        }
        self
    }
    pub fn with_error(&self, error: &str) -> &Self {
        if !self.prop.error.contains(&error.to_string()) {
            self.response.dump_response();
            panic!("Expected error {error}, but got {:?}", self.prop.error);
        }
        self
    }
}

impl DavResponse {
    pub fn into_propfind_response(mut self, prop_prefix: Option<&str>) -> DavMultiStatus {
        if let Some(prop_prefix) = prop_prefix {
            for (key, _) in self.xml.iter_mut() {
                if let Some(suffix) = key.strip_prefix(prop_prefix) {
                    *key = format!("D:multistatus.D:response{suffix}");
                }
            }
            self.xml.push((
                "D:multistatus.D:response.D:href".to_string(),
                "".to_string(),
            ));
        }

        let mut result = DavMultiStatus {
            response: self,
            hrefs: AHashMap::new(),
        };
        let mut href = None;
        let mut href_status = StatusCode::OK;
        let mut props = Vec::new();
        let mut prop = DavItem::default();

        for (key, value) in &result.response.xml {
            match key.as_str() {
                "D:multistatus.D:response.D:href" => {
                    if let Some(href) = href.take() {
                        if !prop.is_empty() {
                            props.push(std::mem::take(&mut prop));
                        }
                        result.hrefs.insert(
                            href,
                            DavProperties {
                                status: href_status,
                                props: std::mem::take(&mut props),
                            },
                        );
                        href_status = StatusCode::OK;
                    }
                    href = Some(value.to_string());
                }
                "D:multistatus.D:response.D:status" => {
                    href_status = value
                        .split_ascii_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .parse()
                        .unwrap();
                }
                "D:multistatus.D:response.D:propstat.D:status" => {
                    prop.status = value
                        .split_ascii_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .parse()
                        .unwrap();
                }
                "D:multistatus.D:response.D:propstat.D:responsedescription" => {
                    prop.description = Some(value.to_string());
                }
                _ => {
                    if let Some(prop_name) =
                        key.strip_prefix("D:multistatus.D:response.D:propstat.D:prop.")
                    {
                        if prop.status != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                            props.push(std::mem::take(&mut prop));
                        }

                        let (prop_name, prop_value) =
                            if let Some((prop_name, prop_sub_name)) = prop_name.split_once('.') {
                                if value.is_empty() {
                                    (prop_name, prop_sub_name.to_string())
                                } else {
                                    (prop_name, format!("{}:{}", prop_sub_name, value))
                                }
                            } else {
                                (prop_name, value.to_string())
                            };
                        prop.values
                            .entry(prop_name.to_string())
                            .or_default()
                            .push(prop_value);
                    }
                }
            }
        }

        if let Some(href) = href.take() {
            if !prop.is_empty() {
                props.push(prop);
            }
            result.hrefs.insert(
                href,
                DavProperties {
                    status: href_status,
                    props,
                },
            );
        }

        result
    }
}

impl DummyWebDavClient {
    pub async fn patch_and_check<T>(
        &self,
        path: &str,
        properties: impl IntoIterator<Item = (T, &str)>,
    ) where
        T: AsRef<str> + Clone,
    {
        let mut expect_set = Vec::new();
        let mut expect_remove = Vec::new();

        for (key, value) in properties {
            if !value.is_empty() {
                expect_set.push((key, value));
            } else {
                expect_remove.push(key);
            }
        }

        let response = self
            .proppatch(
                path,
                expect_set.iter().cloned(),
                expect_remove.iter().cloned(),
                [],
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .into_propfind_response(None);
        let patch_prop = response.properties(path);
        for (key, _) in &expect_set {
            patch_prop.get(key.as_ref()).with_status(StatusCode::OK);
        }
        for key in &expect_remove {
            patch_prop
                .get(key.as_ref())
                .with_status(StatusCode::NO_CONTENT);
        }

        let response = self
            .propfind(
                path,
                expect_set
                    .iter()
                    .map(|(k, _)| k)
                    .chain(expect_remove.iter()),
            )
            .await;
        let prop = response.properties(path);

        for (key, value) in expect_set {
            prop.get(key.as_ref())
                .with_values([value])
                .with_status(StatusCode::OK);
        }

        for key in expect_remove {
            prop.get(key.as_ref()).with_status(StatusCode::NOT_FOUND);
        }
    }

    pub async fn propfind<I, T>(&self, path: &str, properties: I) -> DavMultiStatus
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        self.propfind_with_headers(path, properties, []).await
    }

    pub async fn propfind_with_headers<I, T>(
        &self,
        path: &str,
        properties: I,
        headers: impl IntoIterator<Item = (&'static str, &str)>,
    ) -> DavMultiStatus
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:propfind xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" ",
            "xmlns:B=\"urn:ietf:params:xml:ns:carddav\" xmlns:C=\"http://calendarserver.org/ns/\">",
            "<D:prop>"
        )
        .to_string();

        for property in properties {
            request.push_str(&format!("<{}/>", property.as_ref()));
        }

        request.push_str("</D:prop></D:propfind>");

        self.request_with_headers("PROPFIND", path, headers, &request)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .into_propfind_response(None)
    }

    pub async fn proppatch<T>(
        &self,
        path: &str,
        set: impl IntoIterator<Item = (T, &str)>,
        clear: impl IntoIterator<Item = T>,
        headers: impl IntoIterator<Item = (&'static str, &str)>,
    ) -> DavResponse
    where
        T: AsRef<str>,
    {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" ",
            "xmlns:B=\"urn:ietf:params:xml:ns:carddav\" xmlns:C=\"http://calendarserver.org/ns/\">",
            "<D:remove><D:prop>"
        )
        .to_string();

        for property in clear {
            request.push_str(&format!("<{}/>", property.as_ref()));
        }

        request.push_str("</D:prop></D:remove><D:set><D:prop>");

        for (key, value) in set {
            let key = key.as_ref();
            request.push_str(&format!("<{key}>{value}</{key}>"));
        }

        request.push_str("</D:prop></D:set></D:propertyupdate>");

        self.request_with_headers("PROPPATCH", path, headers, &request)
            .await
    }
}

impl DavItem {
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
            && self.status == StatusCode::PROXY_AUTHENTICATION_REQUIRED
            && self.error.is_empty()
            && self.description.is_none()
    }
}

impl Default for DavItem {
    fn default() -> Self {
        DavItem {
            status: StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            values: AHashMap::new(),
            error: Vec::new(),
            description: None,
        }
    }
}

const EXPAND_REPORT_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:expand-property xmlns:D="DAV:" 
 xmlns:A="urn:ietf:params:xml:ns:caldav" 
 xmlns:B="urn:ietf:params:xml:ns:carddav">
   <A:property name="calendar-description"/>
   <B:property name="addressbook-description"/>
   <D:property name="current-user-principal">
      <D:property name="displayname"/>
   </D:property>
   <D:property name="owner">
      <D:property name="displayname"/>
   </D:property>
</D:expand-property>"#;

pub const ALL_DAV_PROPERTIES: &[DavProperty] = &[
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetContentLanguage),
    DavProperty::WebDav(WebDavProperty::GetContentLength),
    DavProperty::WebDav(WebDavProperty::GetContentType),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes),
    DavProperty::WebDav(WebDavProperty::QuotaUsedBytes),
    DavProperty::WebDav(WebDavProperty::SupportedReportSet),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::Group),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::GetCTag),
    DavProperty::CardDav(CardDavProperty::AddressbookDescription),
    DavProperty::CardDav(CardDavProperty::SupportedAddressData),
    DavProperty::CardDav(CardDavProperty::SupportedCollationSet),
    DavProperty::CardDav(CardDavProperty::MaxResourceSize),
    DavProperty::CalDav(CalDavProperty::CalendarDescription),
    DavProperty::CalDav(CalDavProperty::CalendarTimezone),
    DavProperty::CalDav(CalDavProperty::SupportedCalendarComponentSet),
    DavProperty::CalDav(CalDavProperty::SupportedCalendarData),
    DavProperty::CalDav(CalDavProperty::SupportedCollationSet),
    DavProperty::CalDav(CalDavProperty::MaxResourceSize),
    DavProperty::CalDav(CalDavProperty::MinDateTime),
    DavProperty::CalDav(CalDavProperty::MaxDateTime),
    DavProperty::CalDav(CalDavProperty::MaxInstances),
    DavProperty::CalDav(CalDavProperty::MaxAttendeesPerInstance),
    DavProperty::CalDav(CalDavProperty::TimezoneServiceSet),
    DavProperty::CalDav(CalDavProperty::TimezoneId),
    DavProperty::Principal(PrincipalProperty::AlternateURISet),
    DavProperty::Principal(PrincipalProperty::PrincipalURL),
    DavProperty::Principal(PrincipalProperty::GroupMemberSet),
    DavProperty::Principal(PrincipalProperty::GroupMembership),
    DavProperty::Principal(PrincipalProperty::CalendarHomeSet),
    DavProperty::Principal(PrincipalProperty::AddressbookHomeSet),
    DavProperty::Principal(PrincipalProperty::PrincipalAddress),
];

fn serialize_status_code<S>(status_code: &StatusCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&status_code.to_string())
}
