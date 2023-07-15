/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use futures::{stream::FuturesUnordered, StreamExt};
use jmap_client::{
    client::Client,
    email::{self, Email},
    identity::{self, Identity},
    mailbox::{self, Mailbox},
    sieve::{self, SieveScript},
    vacation_response::{self, VacationResponse},
};
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use super::{cli::ExportCommands, name_to_id, UnwrapResult};

pub async fn cmd_export(mut client: Client, command: ExportCommands) {
    match command {
        ExportCommands::Account {
            num_concurrent,
            account,
            path,
        } => {
            client.set_default_account_id(name_to_id(&client, &account).await);
            let max_objects_in_get = client
                .session()
                .core_capabilities()
                .map(|c| c.max_objects_in_get())
                .unwrap_or(500);

            // Create directory
            let mut path = PathBuf::from(path);
            if !path.is_dir() {
                eprintln!("Directory {} does not exist.", path.display());
                std::process::exit(1);
            }
            path.push(&account);
            if !path.is_dir() {
                std::fs::create_dir(&path).unwrap_or_else(|_| {
                    eprintln!("Failed to create directory: {}", path.display());
                    std::process::exit(1);
                });
            }

            // Export metadata
            let mut blobs = Vec::new();
            export_mailboxes(&client, max_objects_in_get, &path).await;
            export_emails(&client, max_objects_in_get, &mut blobs, &path).await;
            export_sieve_scripts(&client, max_objects_in_get, &mut blobs, &path).await;
            export_identities(&client, &path).await;
            export_vacation_responses(&client, &path).await;

            // Export blobs
            path.push("blobs");
            if !path.exists() {
                std::fs::create_dir(&path).unwrap_or_else(|_| {
                    eprintln!("Failed to create directory: {}", path.display());
                    std::process::exit(1);
                });
            }
            let client = Arc::new(client);
            let num_concurrent = num_concurrent.unwrap_or_else(num_cpus::get);
            let mut futures = FuturesUnordered::new();
            eprintln!("Exporting {} blobs...", blobs.len());
            for blob_id in blobs {
                let client = client.clone();
                let mut blob_path = path.clone();
                blob_path.push(&blob_id);

                futures.push(async move {
                    let bytes = client
                        .download(&blob_id)
                        .await
                        .unwrap_result("download blob");
                    tokio::fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&blob_path)
                        .await
                        .unwrap_result(&format!("open {}", blob_path.display()))
                        .write_all(&bytes)
                        .await
                        .unwrap_result(&format!("write {}", blob_path.display()));
                });

                if futures.len() == num_concurrent {
                    futures.next().await.unwrap();
                }
            }

            // Wait for remaining futures
            while futures.next().await.is_some() {}
        }
    }
}

pub async fn fetch_mailboxes(client: &Client, max_objects_in_get: usize) -> Vec<Mailbox> {
    let mut position = 0;
    let mut results = Vec::new();
    loop {
        let mut request = client.build();
        let query_result = request
            .query_mailbox()
            .calculate_total(true)
            .position(position)
            .limit(max_objects_in_get)
            .result_reference();
        request.get_mailbox().ids_ref(query_result).properties([
            mailbox::Property::Id,
            mailbox::Property::Name,
            mailbox::Property::IsSubscribed,
            mailbox::Property::ParentId,
            mailbox::Property::Role,
            mailbox::Property::SortOrder,
            mailbox::Property::ACL,
        ]);

        let mut response = request
            .send()
            .await
            .unwrap_result("send JMAP request")
            .unwrap_method_responses();
        if response.len() != 2 {
            eprintln!("Invalid response while fetching mailboxes");
            std::process::exit(1);
        }
        let mut get_response = response
            .pop()
            .unwrap()
            .unwrap_get_mailbox()
            .unwrap_result("fetch mailboxes");
        let mailboxes_part = get_response.take_list();
        let total_mailboxes = response
            .pop()
            .unwrap()
            .unwrap_query_mailbox()
            .unwrap_result("query mailboxes")
            .total()
            .unwrap_or(0);

        let mailboxes_part_len = mailboxes_part.len();
        if mailboxes_part_len > 0 {
            results.extend(mailboxes_part);
            if results.len() < total_mailboxes {
                position += mailboxes_part_len as i32;
                continue;
            }
        }
        break;
    }
    results
}

async fn export_mailboxes(client: &Client, max_objects_in_get: usize, path: &Path) {
    eprintln!(
        "Exported {} mailboxes.",
        write_file(
            path,
            "mailboxes.json",
            fetch_mailboxes(client, max_objects_in_get).await,
        )
        .await
    );
}

pub async fn fetch_emails(client: &Client, max_objects_in_get: usize) -> Vec<Email> {
    let mut position = 0;
    let mut results = Vec::new();

    loop {
        let mut request = client.build();
        let query_result = request
            .query_email()
            .calculate_total(true)
            .position(position)
            .limit(max_objects_in_get)
            .result_reference();
        request.get_email().ids_ref(query_result).properties([
            email::Property::Id,
            email::Property::MailboxIds,
            email::Property::Keywords,
            email::Property::ReceivedAt,
            email::Property::BlobId,
            email::Property::MessageId,
        ]);

        let mut response = request
            .send()
            .await
            .unwrap_result("send JMAP request")
            .unwrap_method_responses();
        if response.len() != 2 {
            eprintln!("Invalid response while fetching emails");
            std::process::exit(1);
        }
        let mut get_response = response
            .pop()
            .unwrap()
            .unwrap_get_email()
            .unwrap_result("fetch emails");
        let emails_part = get_response.take_list();
        let total_emails = response
            .pop()
            .unwrap()
            .unwrap_query_email()
            .unwrap_result("query emails")
            .total()
            .unwrap_or(0);

        let emails_part_len = emails_part.len();
        if emails_part_len > 0 {
            results.extend(emails_part);
            if results.len() < total_emails {
                position += emails_part_len as i32;
                continue;
            }
        }
        break;
    }

    results
}

async fn export_emails(
    client: &Client,
    max_objects_in_get: usize,
    blobs: &mut Vec<String>,
    path: &Path,
) {
    let emails = fetch_emails(client, max_objects_in_get).await;

    for email in &emails {
        if let Some(blob_id) = email.blob_id() {
            blobs.push(blob_id.to_string());
        } else {
            eprintln!(
                "Warning: email {:?} has no blobId",
                email.id().unwrap_or_default()
            );
        }
    }

    eprintln!(
        "Exported {} emails.",
        write_file(path, "emails.json", emails,).await
    );
}

pub async fn fetch_sieve_scripts(client: &Client, max_objects_in_get: usize) -> Vec<SieveScript> {
    let mut position = 0;
    let mut results = Vec::new();

    loop {
        let mut request = client.build();
        let query_result = request
            .query_sieve_script()
            .calculate_total(true)
            .position(position)
            .limit(max_objects_in_get)
            .result_reference();
        request
            .get_sieve_script()
            .ids_ref(query_result)
            .properties([
                sieve::Property::Id,
                sieve::Property::Name,
                sieve::Property::BlobId,
                sieve::Property::IsActive,
            ]);

        let mut response = request
            .send()
            .await
            .unwrap_result("send JMAP request")
            .unwrap_method_responses();
        if response.len() != 2 {
            eprintln!("Invalid response while fetching sieve_scripts");
            std::process::exit(1);
        }
        let mut get_response = response
            .pop()
            .unwrap()
            .unwrap_get_sieve_script()
            .unwrap_result("fetch sieve_scripts");
        let sieve_scripts_part = get_response.take_list();
        let total_sieve_scripts = response
            .pop()
            .unwrap()
            .unwrap_query_sieve_script()
            .unwrap_result("query sieve_scripts")
            .total()
            .unwrap_or(0);

        let sieve_scripts_part_len = sieve_scripts_part.len();
        if sieve_scripts_part_len > 0 {
            results.extend(sieve_scripts_part);

            if results.len() < total_sieve_scripts {
                position += sieve_scripts_part_len as i32;
                continue;
            }
        }
        break;
    }
    results
}

async fn export_sieve_scripts(
    client: &Client,
    max_objects_in_get: usize,
    blobs: &mut Vec<String>,
    path: &Path,
) {
    let sieves = fetch_sieve_scripts(client, max_objects_in_get).await;
    for sieve in &sieves {
        if let Some(blob_id) = sieve.blob_id() {
            blobs.push(blob_id.to_string());
        } else {
            eprintln!(
                "Warning: sieve script {:?} has no blobId",
                sieve.id().unwrap_or_default()
            );
        }
    }

    eprintln!(
        "Exported {} sieve scripts.",
        write_file(path, "sieve.json", sieves,).await
    );
}

pub async fn fetch_identities(client: &Client) -> Vec<Identity> {
    let mut request = client.build();
    request.get_identity().properties([
        identity::Property::Id,
        identity::Property::Name,
        identity::Property::Email,
        identity::Property::ReplyTo,
        identity::Property::Bcc,
        identity::Property::TextSignature,
        identity::Property::HtmlSignature,
    ]);
    request
        .send_get_identity()
        .await
        .unwrap_result("send JMAP request")
        .take_list()
}

async fn export_identities(client: &Client, path: &Path) {
    eprintln!(
        "Exported {} identities.",
        write_file(path, "identities.json", fetch_identities(client).await).await
    );
}

pub async fn fetch_vacation_responses(client: &Client) -> Vec<VacationResponse> {
    let mut request = client.build();
    request.get_vacation_response().properties([
        vacation_response::Property::Id,
        vacation_response::Property::FromDate,
        vacation_response::Property::ToDate,
        vacation_response::Property::Subject,
        vacation_response::Property::TextBody,
        vacation_response::Property::HtmlBody,
        vacation_response::Property::IsEnabled,
    ]);
    request
        .send_get_vacation_response()
        .await
        .unwrap_result("send JMAP request")
        .take_list()
}

async fn export_vacation_responses(client: &Client, path: &Path) {
    eprintln!(
        "Exported {} vacation responses.",
        write_file(
            path,
            "vacation.json",
            fetch_vacation_responses(client).await
        )
        .await
    );
}

async fn write_file<T: Serialize>(path: &Path, name: &str, contents: Vec<T>) -> usize {
    let mut path = PathBuf::from(path);
    path.push(name);
    let len = contents.len();
    tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .unwrap_result(&format!("open {}", path.display()))
        .write_all(serde_json::to_string(&contents).unwrap().as_bytes())
        .await
        .unwrap_result(&format!("write to {}", path.display()));
    len
}
