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

use std::{sync::Arc, time::Duration};

use jmap::JMAP;
use jmap_client::{
    client::{Client, Credentials},
    core::set::{SetError, SetErrorType},
    mailbox::{self},
};
use jmap_proto::types::id::Id;

use crate::{
    directory::sql::{create_test_user_with_email, link_test_address},
    jmap::mailbox::destroy_all_mailboxes,
};

pub async fn test(server: Arc<JMAP>, admin_client: &mut Client) {
    println!("Running Authorization tests...");

    // Create test account
    let directory = server.directory.as_ref();
    create_test_user_with_email(directory, "jdoe@example.com", "12345", "John Doe").await;
    let account_id = Id::from(server.get_account_id("jdoe@example.com").await.unwrap()).to_string();
    link_test_address(
        directory,
        "jdoe@example.com",
        "john.doe@example.com",
        "alias",
    )
    .await;

    // Reset rate limiters
    server.rate_limit_auth.clear();
    server.rate_limit_unauth.clear();

    // Incorrect passwords should be rejected with a 401 error
    assert!(matches!(
            Client::new()
                .credentials(Credentials::basic("jdoe@example.com", "abcde"))
                .accept_invalid_certs(true)
                .connect("https://127.0.0.1:8899")
                .await,
            Err(jmap_client::Error::Problem(err)) if err.status() == Some(401)));

    // Invalid authentication requests should be rate limited
    let mut n_401 = 0;
    let mut n_429 = 0;
    for n in 0..110 {
        if let Err(jmap_client::Error::Problem(problem)) = Client::new()
            .credentials(Credentials::basic(
                "not_an_account@example.com",
                &format!("brute_force{}", n),
            ))
            .accept_invalid_certs(true)
            .connect("https://127.0.0.1:8899")
            .await
        {
            if problem.status().unwrap() == 401 {
                n_401 += 1;
                if n_401 > 100 {
                    panic!("Rate limiter failed: 429: {n_429}, 401: {n_401}.");
                }
            } else if problem.status().unwrap() == 429 {
                n_429 += 1;
                if n_429 > 11 {
                    panic!("Rate limiter too restrictive: 429: {n_429}, 401: {n_401}.");
                }
            } else {
                panic!("Unexpected error status {}", problem.status().unwrap());
            }
        } else {
            panic!("Unexpected response.");
        }
    }

    // Limit should be restored after 1 second
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Valid authentication requests should not be rate limited
    for _ in 0..110 {
        Client::new()
            .credentials(Credentials::basic("jdoe@example.com", "12345"))
            .accept_invalid_certs(true)
            .connect("https://127.0.0.1:8899")
            .await
            .unwrap();
    }

    // Login with the correct credentials
    let client = Client::new()
        .credentials(Credentials::basic("jdoe@example.com", "12345"))
        .accept_invalid_certs(true)
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(client.session().username(), "jdoe@example.com");
    assert_eq!(
        client.session().account(&account_id).unwrap().name(),
        "John Doe"
    );
    assert!(client.session().account(&account_id).unwrap().is_personal());

    // Uploads up to 50000000 bytes should be allowed
    assert_eq!(
        client
            .upload(None, vec![b'A'; 5000000], None)
            .await
            .unwrap()
            .size(),
        5000000
    );
    assert!(client
        .upload(None, vec![b'A'; 5000001], None)
        .await
        .is_err());

    // Users should be allowed to create identities only
    // using email addresses associated to their principal
    let iid1 = client
        .identity_create("John Doe", "jdoe@example.com")
        .await
        .unwrap()
        .take_id();
    let iid2 = client
        .identity_create("John Doe (secondary)", "john.doe@example.com")
        .await
        .unwrap()
        .take_id();
    assert!(matches!(
        client
            .identity_create("John the Spammer", "spammy@mcspamface.com")
            .await,
        Err(jmap_client::Error::Set(SetError {
            type_: SetErrorType::InvalidProperties,
            ..
        }))
    ));
    client.identity_destroy(&iid1).await.unwrap();
    client.identity_destroy(&iid2).await.unwrap();

    // Concurrent requests check
    let client = Arc::new(client);
    for _ in 0..8 {
        let client_ = client.clone();
        tokio::spawn(async move {
            client_
                .mailbox_query(
                    mailbox::query::Filter::name("__sleep").into(),
                    [mailbox::query::Comparator::name()].into(),
                )
                .await
                .unwrap();
        });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        client
            .mailbox_query(
                mailbox::query::Filter::name("__sleep").into(),
                [mailbox::query::Comparator::name()].into(),
            )
            .await,
            Err(jmap_client::Error::Problem(err)) if err.status() == Some(400)));

    // Wait for sleep to be done
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Concurrent upload test
    for _ in 0..4 {
        let client_ = client.clone();
        tokio::spawn(async move {
            client_.upload(None, b"sleep".to_vec(), None).await.unwrap();
        });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        client.upload(None, b"sleep".to_vec(), None).await,
        Err(jmap_client::Error::Problem(err)) if err.status() == Some(400)));

    // Destroy test accounts
    admin_client.set_default_account_id(&account_id);
    destroy_all_mailboxes(admin_client).await;
    server.store.assert_is_empty().await;
}
