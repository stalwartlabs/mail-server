/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{fs, path::PathBuf, sync::Arc};

use jmap::JMAP;
use jmap_client::{
    client::Client,
    email::{self, Header, HeaderForm},
    mailbox::Role,
};
use jmap_proto::types::id::Id;
use mail_parser::{HeaderName, RfcHeader};

use crate::jmap::replace_blob_ids;

pub async fn test(server: Arc<JMAP>, client: &mut Client) {
    println!("Running Email Get tests...");

    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("resources");
    test_dir.push("jmap_mail_get");

    let coco1 = "implement";
    let mailbox_id = "a".to_string();
    /*let mailbox_id = client
    .set_default_account_id(Id::new(1).to_string())
    .mailbox_create("JMAP Get", None::<String>, Role::None)
    .await
    .unwrap()
    .take_id();*/

    for file_name in fs::read_dir(&test_dir).unwrap() {
        let mut file_name = file_name.as_ref().unwrap().path();
        if file_name.extension().map_or(true, |e| e != "eml") {
            continue;
        }
        let is_headers_test = file_name.file_name().unwrap() == "headers.eml";

        let blob = fs::read(&file_name).unwrap();
        let blob_len = blob.len();
        let email = client
            .email_import(
                blob,
                [mailbox_id.clone()],
                ["tag".to_string()].into(),
                ((blob_len * 1000000) as i64).into(),
            )
            .await
            .unwrap();

        let mut request = client.build();
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
                let mut request = client.build();
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

    let coco = "implement";
    //client.mailbox_destroy(&mailbox_id, true).await.unwrap();

    //server.store.assert_is_empty();
}

pub fn all_headers() -> Vec<email::Property> {
    let mut properties = Vec::new();

    for header in [
        HeaderName::Rfc(RfcHeader::From),
        HeaderName::Rfc(RfcHeader::To),
        HeaderName::Rfc(RfcHeader::Cc),
        HeaderName::Rfc(RfcHeader::Bcc),
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
        HeaderName::Rfc(RfcHeader::ListPost),
        HeaderName::Rfc(RfcHeader::ListSubscribe),
        HeaderName::Rfc(RfcHeader::ListUnsubscribe),
        HeaderName::Rfc(RfcHeader::ListOwner),
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
        HeaderName::Rfc(RfcHeader::Date),
        HeaderName::Rfc(RfcHeader::ResentDate),
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
        HeaderName::Rfc(RfcHeader::MessageId),
        HeaderName::Rfc(RfcHeader::References),
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
        HeaderName::Rfc(RfcHeader::Subject),
        HeaderName::Rfc(RfcHeader::Keywords),
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
