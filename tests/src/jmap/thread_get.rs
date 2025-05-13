/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{assert_is_empty, mailbox::destroy_all_mailboxes};
use jmap_client::mailbox::Role;
use jmap_proto::types::id::Id;

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email Thread tests...");
    let server = params.server.clone();

    let mailbox_id = params
        .client
        .set_default_account_id(Id::new(1).to_string())
        .mailbox_create("JMAP Get", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    let mut expected_result = vec!["".to_string(); 5];
    let mut thread_id = "".to_string();

    for num in [5, 3, 1, 2, 4] {
        let mut email = params
            .client
            .email_import(
                format!("Subject: test\nReferences: <1234>\n\n{}", num).into_bytes(),
                [&mailbox_id],
                None::<Vec<String>>,
                Some(10000i64 + num as i64),
            )
            .await
            .unwrap();
        thread_id = email.thread_id().unwrap().to_string();
        expected_result[num - 1] = email.take_id();
    }

    assert_eq!(
        params
            .client
            .thread_get(&thread_id)
            .await
            .unwrap()
            .unwrap()
            .email_ids(),
        expected_result
    );

    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
}
