/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fs, path::PathBuf};

use jmap::mailbox::INBOX_ID;
use jmap_client::email::{self, import::EmailImportResponse, Header, HeaderForm};
use jmap_proto::types::id::Id;
use mail_parser::HeaderName;

use crate::jmap::{assert_is_empty, mailbox::destroy_all_mailboxes, replace_blob_ids};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email Get tests...");
    let server = params.server.clone();

    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("resources");
    test_dir.push("jmap");
    test_dir.push("email_get");

    let mailbox_id = Id::from(INBOX_ID).to_string();
    params.client.set_default_account_id(Id::from(1u64));

    for file_name in fs::read_dir(&test_dir).unwrap() {
        let mut file_name = file_name.as_ref().unwrap().path();
        if file_name.extension().map_or(true, |e| e != "eml") {
            continue;
        }
        let is_headers_test = file_name.file_name().unwrap() == "headers.eml";

        let blob = fs::read(&file_name).unwrap();
        let blob_len = blob.len();

        // Import email
        let mut request = params.client.build();
        let import_request = request
            .import_email()
            .account_id(Id::from(1u64).to_string())
            .email(
                params
                    .client
                    .upload(None, blob, None)
                    .await
                    .unwrap()
                    .take_blob_id(),
            )
            .mailbox_ids([mailbox_id.clone()])
            .keywords(["tag".to_string()])
            .received_at((blob_len * 1000000) as i64);
        let id = import_request.create_id();
        let mut response = request.send_single::<EmailImportResponse>().await.unwrap();
        assert_ne!(response.old_state(), Some(response.new_state()));
        let email = response.created(&id).unwrap();

        let mut request = params.client.build();
        request
            .get_email()
            .ids([email.id().unwrap()])
            .properties([
                email::Property::Id,
                email::Property::BlobId,
                email::Property::ThreadId,
                email::Property::MailboxIds,
                email::Property::Keywords,
                email::Property::Size,
                email::Property::ReceivedAt,
                email::Property::MessageId,
                email::Property::InReplyTo,
                email::Property::References,
                email::Property::Sender,
                email::Property::From,
                email::Property::To,
                email::Property::Cc,
                email::Property::Bcc,
                email::Property::ReplyTo,
                email::Property::Subject,
                email::Property::SentAt,
                email::Property::HasAttachment,
                email::Property::Preview,
                email::Property::BodyValues,
                email::Property::TextBody,
                email::Property::HtmlBody,
                email::Property::Attachments,
                email::Property::BodyStructure,
            ])
            .arguments()
            .body_properties(if !is_headers_test {
                [
                    email::BodyProperty::PartId,
                    email::BodyProperty::BlobId,
                    email::BodyProperty::Size,
                    email::BodyProperty::Name,
                    email::BodyProperty::Type,
                    email::BodyProperty::Charset,
                    email::BodyProperty::Headers,
                    email::BodyProperty::Disposition,
                    email::BodyProperty::Cid,
                    email::BodyProperty::Language,
                    email::BodyProperty::Location,
                ]
            } else {
                [
                    email::BodyProperty::PartId,
                    email::BodyProperty::Size,
                    email::BodyProperty::Name,
                    email::BodyProperty::Type,
                    email::BodyProperty::Charset,
                    email::BodyProperty::Disposition,
                    email::BodyProperty::Cid,
                    email::BodyProperty::Language,
                    email::BodyProperty::Location,
                    email::BodyProperty::Header(Header {
                        name: "X-Custom-Header".into(),
                        form: HeaderForm::Raw,
                        all: false,
                    }),
                    email::BodyProperty::Header(Header {
                        name: "X-Custom-Header-2".into(),
                        form: HeaderForm::Raw,
                        all: false,
                    }),
                ]
            })
            .fetch_all_body_values(true)
            .max_body_value_bytes(100);

        let mut result = request
            .send_get_email()
            .await
            .unwrap()
            .take_list()
            .pop()
            .unwrap()
            .into_test();

        if is_headers_test {
            for property in all_headers() {
                let mut request = params.client.build();
                request
                    .get_email()
                    .ids([email.id().unwrap()])
                    .properties([property]);
                result.headers.extend(
                    request
                        .send_get_email()
                        .await
                        .unwrap()
                        .take_list()
                        .pop()
                        .unwrap()
                        .into_test()
                        .headers,
                );
            }
        }

        let result = replace_blob_ids(serde_json::to_string_pretty(&result).unwrap());

        file_name.set_extension("json");

        if fs::read(&file_name).unwrap() != result.as_bytes() {
            file_name.set_extension("failed");
            fs::write(&file_name, result.as_bytes()).unwrap();
            panic!("Test failed, output saved to {}", file_name.display());
        }
    }

    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
}

pub fn all_headers() -> Vec<email::Property> {
    let mut properties = Vec::new();

    for header in [
        HeaderName::From,
        HeaderName::To,
        HeaderName::Cc,
        HeaderName::Bcc,
        HeaderName::Other("X-Address-Single".into()),
        HeaderName::Other("X-Address".into()),
        HeaderName::Other("X-AddressList-Single".into()),
        HeaderName::Other("X-AddressList".into()),
        HeaderName::Other("X-AddressesGroup-Single".into()),
        HeaderName::Other("X-AddressesGroup".into()),
    ] {
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: false,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Addresses,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Addresses,
            name: header.as_str().to_string(),
            all: false,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::GroupedAddresses,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::GroupedAddresses,
            name: header.as_str().to_string(),
            all: false,
        }));
    }

    for header in [
        HeaderName::ListPost,
        HeaderName::ListSubscribe,
        HeaderName::ListUnsubscribe,
        HeaderName::ListOwner,
        HeaderName::Other("X-List-Single".into()),
        HeaderName::Other("X-List".into()),
    ] {
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: false,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::URLs,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::URLs,
            name: header.as_str().to_string(),
            all: false,
        }));
    }

    for header in [
        HeaderName::Date,
        HeaderName::ResentDate,
        HeaderName::Other("X-Date-Single".into()),
        HeaderName::Other("X-Date".into()),
    ] {
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: false,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Date,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Date,
            name: header.as_str().to_string(),
            all: false,
        }));
    }

    for header in [
        HeaderName::MessageId,
        HeaderName::References,
        HeaderName::Other("X-Id-Single".into()),
        HeaderName::Other("X-Id".into()),
    ] {
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: false,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::MessageIds,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::MessageIds,
            name: header.as_str().to_string(),
            all: false,
        }));
    }

    for header in [
        HeaderName::Subject,
        HeaderName::Keywords,
        HeaderName::Other("X-Text-Single".into()),
        HeaderName::Other("X-Text".into()),
    ] {
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Raw,
            name: header.as_str().to_string(),
            all: false,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Text,
            name: header.as_str().to_string(),
            all: true,
        }));
        properties.push(email::Property::Header(Header {
            form: HeaderForm::Text,
            name: header.as_str().to_string(),
            all: false,
        }));
    }

    properties
}
