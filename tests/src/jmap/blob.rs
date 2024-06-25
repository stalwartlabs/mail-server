/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::backend::internal::manage::ManageDirectory;
use jmap::mailbox::INBOX_ID;
use jmap_proto::types::id::Id;
use serde_json::Value;

use crate::jmap::{assert_is_empty, jmap_json_request, mailbox::destroy_all_mailboxes};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running blob tests...");
    let server = params.server.clone();
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "12345", "John Doe")
        .await;
    let account_id = Id::from(
        server
            .core
            .storage
            .data
            .get_or_create_account_id("jdoe@example.com")
            .await
            .unwrap(),
    );

    server.core.storage.data.blob_expire_all().await;

    // Blob/set simple test
    let response = jmap_json_request(
        r#"[[
            "Blob/upload",
            {
             "accountId": "$$",
             "create": {
              "abc": {
               "data" : [
               {
                "data:asBase64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQMAAAAl21bKAAAAA1BMVEX/AAAZ4gk3AAAAAXRSTlN/gFy0ywAAAApJREFUeJxjYgAAAAYAAzY3fKgAAAAASUVORK5CYII="
               }
              ],
              "type": "image/png"
              }
             }
            },
            "R1"
           ]]"#
            .replace("$$", &account_id.to_string()),
        "jdoe@example.com",
        "12345",
    )
    .await;
    assert_eq!(
        response
            .pointer("/methodResponses/0/1/created/abc/type")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "image/png",
        "Response: {:?}",
        response
    );
    assert_eq!(
        response
            .pointer("/methodResponses/0/1/created/abc/size")
            .and_then(|v| v.as_i64())
            .unwrap_or_default(),
        95,
        "Response: {:?}",
        response
    );

    // Blob/get simple test
    let blob_id = jmap_json_request(
        r#"[[
            "Blob/upload",
            {
             "accountId": "$$",
             "create": {
              "abc": {
               "data" : [
               {
                "data:asText": "The quick brown fox jumped over the lazy dog."
               }
              ]
              }
             }
            },
            "R1"
           ]]"#
        .replace("$$", &account_id.to_string()),
        "jdoe@example.com",
        "12345",
    )
    .await
    .pointer("/methodResponses/0/1/created/abc/id")
    .and_then(|v| v.as_str())
    .unwrap()
    .to_string();

    let response = jmap_json_request(
        r#"[
            [
              "Blob/get",
              {
                "accountId" : "$$",
                "ids" : [
                  "%%"
                ],
                "properties" : [
                  "data:asText",
                  "digest:sha",
                  "size"
                ]
              },
              "R1"
            ],
            [
              "Blob/get",
              {
                "accountId" : "$$",
                "ids" : [
                  "%%"
                ],
                "properties" : [
                  "data:asText",
                  "digest:sha",
                  "digest:sha-256",
                  "size"
                ],
                "offset" : 4,
                "length" : 9
              },
              "R2"
            ]
          ]"#
        .replace("$$", &account_id.to_string())
        .replace("%%", &blob_id),
        "jdoe@example.com",
        "12345",
    )
    .await;

    for (pointer, expected) in [
        (
            "/methodResponses/0/1/list/0/data:asText",
            "The quick brown fox jumped over the lazy dog.",
        ),
        (
            "/methodResponses/0/1/list/0/digest:sha",
            "wIVPufsDxBzOOALLDSIFKebu+U4=",
        ),
        ("/methodResponses/0/1/list/0/size", "45"),
        ("/methodResponses/1/1/list/0/data:asText", "quick bro"),
        (
            "/methodResponses/1/1/list/0/digest:sha",
            "QiRAPtfyX8K6tm1iOAtZ87Xj3Ww=",
        ),
        (
            "/methodResponses/1/1/list/0/digest:sha-256",
            "gdg9INW7lwHK6OQ9u0dwDz2ZY/gubi0En0xlFpKt0OA=",
        ),
    ] {
        assert_eq!(
            response
                .pointer(pointer)
                .and_then(|v| match v {
                    Value::String(s) => Some(s.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .unwrap_or_default(),
            expected,
            "Pointer {pointer:?} Response: {response:?}",
        );
    }

    server.core.storage.data.blob_expire_all().await;

    // Blob/upload Complex Example
    let response = jmap_json_request(
        r##"[
            [
             "Blob/upload",
             {
              "accountId" : "$$",
              "create": {
               "b4": {
                "data": [
                 {
                  "data:asText": "The quick brown fox jumped over the lazy dog."
                 }
               ]
              }
             }
            },
            "S4"
           ],
           [
             "Blob/upload",
             {
              "accountId" : "$$",
              "create": {
                "cat": {
                  "data": [
                    {
                      "data:asText": "How"
                    },
                    {
                      "blobId": "#b4",
                      "length": 7,
                      "offset": 3
                    },
                    {
                      "data:asText": "was t"
                    },
                    {
                      "blobId": "#b4",
                      "length": 1,
                      "offset": 1
                    },
                    {
                      "data:asBase64": "YXQ/"
                    }
                  ]
                }
              }
             },
             "CAT"
           ],
           [
             "Blob/get",
             {
              "accountId" : "$$",
              "properties": [
                "data:asText",
                "size"
              ],
              "ids": [
                "#cat"
              ]
             },
             "G4"
            ]
           ]"##
        .replace("$$", &account_id.to_string()),
        "jdoe@example.com",
        "12345",
    )
    .await;

    for (pointer, expected) in [
        (
            "/methodResponses/2/1/list/0/data:asText",
            "How quick was that?",
        ),
        ("/methodResponses/2/1/list/0/size", "19"),
    ] {
        assert_eq!(
            response
                .pointer(pointer)
                .and_then(|v| match v {
                    Value::String(s) => Some(s.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .unwrap_or_default(),
            expected,
            "Pointer {pointer:?} Response: {response:?}",
        );
    }
    server.core.storage.data.blob_expire_all().await;

    // Blob/get Example with Range and Encoding Errors
    let response = jmap_json_request(
        r##"[
            [
              "Blob/upload",
              {
                "accountId" : "$$",
                "create": {
                  "b1": {
                    "data": [
                      {
                        "data:asBase64": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUggYEgZG9nLg=="
                      }
                    ]
                  },
                  "b2": {
                    "data": [
                      {
                        "data:asText": "hello world"
                      }
                    ],
                    "type" : "text/plain"
                  }
                }
              },
              "S1"
            ],
            [
              "Blob/get",
              {
                "accountId" : "$$",
                "ids": [
                  "#b1",
                  "#b2"
                ]
              },
              "G1"
            ],
            [
              "Blob/get",
              {
                "accountId" : "$$",
                "ids": [
                  "#b1",
                  "#b2"
                ],
                "properties": [
                  "data:asText",
                  "size"
                ]
              },
              "G2"
            ],
            [
              "Blob/get",
              {
                "accountId" : "$$",
                "ids": [
                  "#b1",
                  "#b2"
                ],
                "properties": [
                  "data:asBase64",
                  "size"
                ]
              },
              "G3"
            ],
            [
              "Blob/get",
              {
                "accountId" : "$$",
                "offset": 0,
                "length": 5,
                "ids": [
                  "#b1",
                  "#b2"
                ]
              },
              "G4"
            ],
            [
              "Blob/get",
              {
                "accountId" : "$$",
                "offset": 20,
                "length": 100,
                "ids": [
                  "#b1",
                  "#b2"
                ]
              },
              "G5"
            ]
          ]"##
        .replace("$$", &account_id.to_string()),
        "jdoe@example.com",
        "12345",
    )
    .await;

    for (pointer, expected) in [
        (
            "/methodResponses/1/1/list/0/data:asBase64",
            "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUggYEgZG9nLg==",
        ),
        ("/methodResponses/1/1/list/1/data:asText", "hello world"),
        ("/methodResponses/2/1/list/0/isEncodingProblem", "true"),
        ("/methodResponses/2/1/list/1/data:asText", "hello world"),
        (
            "/methodResponses/3/1/list/0/data:asBase64",
            "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUggYEgZG9nLg==",
        ),
        (
            "/methodResponses/3/1/list/1/data:asBase64",
            "aGVsbG8gd29ybGQ=",
        ),
        ("/methodResponses/4/1/list/0/data:asText", "The q"),
        ("/methodResponses/4/1/list/1/data:asText", "hello"),
        ("/methodResponses/5/1/list/0/isEncodingProblem", "true"),
        ("/methodResponses/5/1/list/0/isTruncated", "true"),
        ("/methodResponses/5/1/list/1/isTruncated", "true"),
    ] {
        assert_eq!(
            response
                .pointer(pointer)
                .and_then(|v| match v {
                    Value::String(s) => Some(s.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
                .unwrap_or_default(),
            expected,
            "Pointer {pointer:?} Response: {response:?}",
        );
    }
    server.core.storage.data.blob_expire_all().await;

    // Blob/lookup
    params.client.set_default_account_id(account_id.to_string());
    let blob_id = params
        .client
        .email_import(
            concat!(
                "From: bill@example.com\r\n",
                "To: jdoe@example.com\r\n",
                "Subject: TPS Report\r\n",
                "\r\n",
                "I'm going to need those TPS reports ASAP. ",
                "So, if you could do that, that'd be great."
            )
            .as_bytes()
            .to_vec(),
            [&Id::from(INBOX_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_blob_id();

    let response = jmap_json_request(
        r#"[[
                "Blob/lookup",
                {
                  "accountId" : "$$",
                  "typeNames": [
                    "Mailbox",
                    "Thread",
                    "Email"
                  ],
                  "ids": [
                    "%%",
                    "not-a-blob"
                  ]
                },
                "R1"
              ]]"#
        .replace("$$", &account_id.to_string())
        .replace("%%", &blob_id),
        "jdoe@example.com",
        "12345",
    )
    .await;

    for pointer in [
        "/methodResponses/0/1/list/0/matchedIds/Email",
        "/methodResponses/0/1/list/0/matchedIds/Mailbox",
        "/methodResponses/0/1/list/0/matchedIds/Thread",
    ] {
        assert_eq!(
            response
                .pointer(pointer)
                .and_then(|v| v.as_array())
                .map(|arr| arr.len())
                .unwrap_or_default(),
            1,
            "Pointer {pointer:?} Response: {response:#?}",
        );
    }

    // Remove test data
    params.client.set_default_account_id(account_id.to_string());
    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
}
