use std::sync::Arc;

use jmap::JMAP;
use jmap_client::{client::Client, email, mailbox::Role};
use jmap_proto::types::id::Id;
use store::ahash::{AHashMap, AHashSet};

pub async fn test(server: Arc<JMAP>, client: &mut Client) {
    println!("Running Email Merge Threads tests...");

    simple_test(client).await;

    let mut all_mailboxes = AHashMap::default();

    for (base_test_num, test) in [test_1(), test_2(), test_3()].iter().enumerate() {
        let base_test_num = ((base_test_num * 6) as u32) + 1;
        let mut messages = Vec::new();
        let mut total_messages = 0;
        let mut messages_per_thread =
            build_messages(test, &mut messages, &mut total_messages, None, 0);
        messages_per_thread.sort_unstable();

        let mut mailbox_ids = Vec::with_capacity(6);

        for test_num in 0..=5 {
            mailbox_ids.push(char::from(b'a' + test_num as u8).to_string());
            let coco = "fd";
            /*mailbox_ids.push(
                client
                    .set_default_account_id(Id::new((base_test_num + test_num) as u64).to_string())
                    .mailbox_create("Thread nightmare", None::<String>, Role::None)
                    .await
                    .unwrap()
                    .take_id(),
            );*/
        }

        for message in &messages {
            client
                .set_default_account_id(Id::new(base_test_num as u64).to_string())
                .email_import(
                    message.to_string().into_bytes(),
                    [mailbox_ids[0].clone()],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap();
        }

        for message in messages.iter().rev() {
            client
                .set_default_account_id(Id::new((base_test_num + 1) as u64).to_string())
                .email_import(
                    message.to_string().into_bytes(),
                    [mailbox_ids[1].clone()],
                    None::<Vec<String>>,
                    None,
                )
                .await
                .unwrap();
        }

        for chunk in messages.chunks(5) {
            client.set_default_account_id(Id::new((base_test_num + 2) as u64).to_string());

            for message in chunk {
                client
                    .email_import(
                        message.to_string().into_bytes(),
                        [mailbox_ids[2].clone()],
                        None::<Vec<String>>,
                        None,
                    )
                    .await
                    .unwrap();
            }

            client.set_default_account_id(Id::new((base_test_num + 3) as u64).to_string());

            for message in chunk.iter().rev() {
                client
                    .email_import(
                        message.to_string().into_bytes(),
                        [mailbox_ids[3].clone()],
                        None::<Vec<String>>,
                        None,
                    )
                    .await
                    .unwrap();
            }
        }

        for chunk in messages.chunks(5).rev() {
            client.set_default_account_id(Id::new((base_test_num + 4) as u64).to_string());

            for message in chunk {
                client
                    .email_import(
                        message.to_string().into_bytes(),
                        [mailbox_ids[4].clone()],
                        None::<Vec<String>>,
                        None,
                    )
                    .await
                    .unwrap();
            }

            client.set_default_account_id(Id::new((base_test_num + 5) as u64).to_string());

            for message in chunk.iter().rev() {
                client
                    .email_import(
                        message.to_string().into_bytes(),
                        [mailbox_ids[5].clone()],
                        None::<Vec<String>>,
                        None,
                    )
                    .await
                    .unwrap();
            }
        }

        for test_num in 0..=5 {
            let result = client
                .set_default_account_id(Id::new((base_test_num + test_num) as u64).to_string())
                .email_query(
                    email::query::Filter::in_mailbox(mailbox_ids[test_num as usize].clone()).into(),
                    None::<Vec<_>>,
                )
                .await
                .unwrap();

            assert_eq!(
                result.ids().len(),
                total_messages,
                "test# {}/{}",
                base_test_num,
                test_num
            );

            let thread_ids: AHashSet<u32> = result
                .ids()
                .iter()
                .map(|id| Id::from_bytes(id.as_bytes()).unwrap().prefix_id())
                .collect();

            assert_eq!(
                thread_ids.len(),
                messages_per_thread.len(),
                "{:?}: test# {}/{}",
                thread_ids,
                base_test_num,
                test_num
            );

            let mut messages_per_thread_db = Vec::new();

            for thread_id in thread_ids {
                messages_per_thread_db.push(
                    client
                        .thread_get(&Id::new(thread_id as u64).to_string())
                        .await
                        .unwrap()
                        .unwrap()
                        .email_ids()
                        .len(),
                );
            }
            messages_per_thread_db.sort_unstable();

            assert_eq!(messages_per_thread_db, messages_per_thread);
            println!("passed test# {}/{}", base_test_num, test_num);
        }

        all_mailboxes.insert(base_test_num as usize, mailbox_ids);
    }

    // Delete all messages and make sure no keys are left in the store.
    let implement = "fdf";
    /*for (base_test_num, mailbox_ids) in all_mailboxes {
        for (test_num, mailbox_id) in mailbox_ids.into_iter().enumerate() {
            client
                .set_default_account_id(Id::new((base_test_num + test_num) as u64).to_string())
                .mailbox_destroy(&mailbox_id, true)
                .await
                .unwrap();
        }
    }

    server.store.assert_is_empty();*/
}

async fn simple_test(client: &mut Client) {
    let coco = "fdf";
    let mailbox_id = "a".to_string();
    /*
    let mailbox_id = client
        .set_default_account_id(Id::new(1).to_string())
        .mailbox_create("JMAP Get", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();*/

    // A simple thread that uses in-reply-to to link messages together
    let thread_1 = vec![
        client
            .email_import(
                "Message-ID: <t1-msg1>
From: test1@example.com
To: test2@example.com
Subject: my thread

message here!"
                    .into(),
                [&mailbox_id],
                None::<Vec<String>>,
                Some(1),
            )
            .await
            .unwrap(),
        client
            .email_import(
                "Message-ID: <t1-msg2>
From: test2@example.com
To: test1@example.com
In-Reply-To: <t1-msg1>
Subject: Re: my thread

reply here!"
                    .into(),
                [&mailbox_id],
                None::<Vec<String>>,
                Some(2),
            )
            .await
            .unwrap(),
        client
            .email_import(
                "Message-ID: <t1-msg3>
From: test1@example.com
To: test2@example.com
In-Reply-To: <t1-msg2>
Subject: Re: my thread

last reply"
                    .into(),
                [&mailbox_id],
                None::<Vec<String>>,
                Some(3),
            )
            .await
            .unwrap(),
    ];

    // Another simple thread, but this time with a shared reference header instead
    let thread_2 = vec![
        client
            .email_import(
                "Message-ID: <t2-msg1>
From: test1@example.com
To: test2@example.com
Subject: my thread

message here!"
                    .into(),
                [&mailbox_id],
                None::<Vec<String>>,
                Some(1),
            )
            .await
            .unwrap(),
        client
            .email_import(
                "Message-ID: <t2-msg2>
References: <t2-msg1>
From: test2@example.com
To: test1@example.com
Subject: my thread

reply here!"
                    .into(),
                [&mailbox_id],
                None::<Vec<String>>,
                Some(2),
            )
            .await
            .unwrap(),
        client
            .email_import(
                "Message-ID: <t2-msg3>
References: <t2-msg1>
From: test1@example.com
To: test2@example.com
Subject: my thread

reply here!"
                    .into(),
                [&mailbox_id],
                None::<Vec<String>>,
                Some(3),
            )
            .await
            .unwrap(),
    ];

    // Make sure none of the separate threads end up with the same thread ID
    assert_ne!(
        thread_1.first().unwrap().thread_id().unwrap(),
        thread_2.first().unwrap().thread_id().unwrap(),
        "Making sure thread 1 and thread 2 have different thread IDs"
    );

    // Make sure each message in each thread ends up with the right thread ID
    assert_thread_ids_match(client, &thread_1, "thread chained with In-Reply-To header").await;
    assert_thread_ids_match(client, &thread_2, "thread with References header").await;

    //client.mailbox_destroy(&mailbox_id, true).await.unwrap();
}

async fn assert_thread_ids_match(
    client: &mut Client,
    emails: &Vec<jmap_client::email::Email>,
    description: &str,
) {
    let thread_id = emails.first().unwrap().thread_id().unwrap();

    // First, make sure the thread ID is the same for all messages in the thread
    for email in emails {
        assert_eq!(
            email.thread_id().unwrap(),
            thread_id,
            "Comparing thread IDs of messages in: {}",
            description
        );
    }

    // Next, make sure querying the thread yields the same messages
    let full_thread = client.thread_get(thread_id).await.unwrap().unwrap();
    let mut email_ids_in_fetched_thread = full_thread.email_ids().to_vec();
    email_ids_in_fetched_thread.sort();

    let mut expected_email_ids = emails
        .iter()
        .map(|email| email.id().unwrap())
        .collect::<Vec<_>>();
    expected_email_ids.sort();

    assert_eq!(
        email_ids_in_fetched_thread, expected_email_ids,
        "Comparing email IDs in: {}",
        description
    );
}

fn build_message(message: usize, in_reply_to: Option<usize>, thread_num: usize) -> String {
    if let Some(in_reply_to) = in_reply_to {
        format!(
            "Message-ID: <{}>\nReferences: <{}>\nSubject: re: T{}\n\nreply\n",
            message, in_reply_to, thread_num
        )
    } else {
        format!(
            "Message-ID: <{}>\nSubject: T{}\n\nmsg\n",
            message, thread_num
        )
    }
}

fn build_messages(
    three: &ThreadTest,
    messages: &mut Vec<String>,
    total_messages: &mut usize,
    in_reply_to: Option<usize>,
    thread_num: usize,
) -> Vec<usize> {
    let mut messages_per_thread = Vec::new();
    match three {
        ThreadTest::Message => {
            *total_messages += 1;
            messages.push(build_message(*total_messages, in_reply_to, thread_num));
        }
        ThreadTest::MessageWithReplies(replies) => {
            *total_messages += 1;
            messages.push(build_message(*total_messages, in_reply_to, thread_num));
            let in_reply_to = Some(*total_messages);
            for reply in replies {
                build_messages(reply, messages, total_messages, in_reply_to, thread_num);
            }
        }
        ThreadTest::Root(items) => {
            for (thread_num, item) in items.iter().enumerate() {
                let count_start = *total_messages;
                build_messages(item, messages, total_messages, None, thread_num);
                messages_per_thread.push(*total_messages - count_start);
            }
        }
    }
    messages_per_thread
}

pub fn build_thread_test_messages() -> Vec<String> {
    let mut messages = Vec::new();
    let mut total_messages = 0;
    build_messages(&test_3(), &mut messages, &mut total_messages, None, 0);
    messages
}

pub enum ThreadTest {
    Message,
    MessageWithReplies(Vec<ThreadTest>),
    Root(Vec<ThreadTest>),
}

fn test_1() -> ThreadTest {
    ThreadTest::Root(vec![
        ThreadTest::Message,
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::Message,
            ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::Message,
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ]),
                    ]),
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::Message,
                            ThreadTest::Message,
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::Message,
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ])
}

fn test_2() -> ThreadTest {
    ThreadTest::Root(vec![
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::Message,
            ThreadTest::Message,
            ThreadTest::Message,
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                    ThreadTest::Message,
                                ]),
                                ThreadTest::Message,
                            ]),
                            ThreadTest::Message,
                        ]),
                        ThreadTest::Message,
                    ]),
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                    ]),
                                ],
                            )]),
                            ThreadTest::Message,
                        ]),
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                    ]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                        ThreadTest::Message,
                                        ThreadTest::Message,
                                    ]),
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ]),
                            ]),
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ])]),
                    ]),
                ]),
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ]),
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                    ]),
                                    ThreadTest::Message,
                                ]),
                            ]),
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                ]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                ]),
                                ThreadTest::Message,
                                ThreadTest::Message,
                            ]),
                        ]),
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ]),
                                ThreadTest::Message,
                                ThreadTest::Message,
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                            ]),
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                        ThreadTest::Message,
                                    ]),
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ]),
                            ]),
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ]),
                    ]),
                    ThreadTest::Message,
                    ThreadTest::Message,
                ]),
            ]),
        ]),
        ThreadTest::Message,
        ThreadTest::MessageWithReplies(vec![ThreadTest::Message, ThreadTest::Message]),
    ])
}

fn test_3() -> ThreadTest {
    ThreadTest::Root(vec![
        ThreadTest::MessageWithReplies(vec![ThreadTest::Message, ThreadTest::Message]),
        ThreadTest::Message,
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::Message,
                    ThreadTest::Message,
                ]),
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                ThreadTest::Message,
            ]),
            ThreadTest::Message,
            ThreadTest::Message,
        ]),
        ThreadTest::Message,
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ])],
                            )]),
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ])]),
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::Message,
                                ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                    ]),
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                        ThreadTest::Message,
                                    ]),
                                ]),
                            ]),
                        ]),
                    ]),
                    ThreadTest::Message,
                    ThreadTest::Message,
                ])]),
                ThreadTest::Message,
            ]),
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                ])]),
                ThreadTest::Message,
            ]),
        ]),
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                ThreadTest::Message,
                ThreadTest::MessageWithReplies(vec![ThreadTest::Message, ThreadTest::Message]),
                ThreadTest::Message,
                ThreadTest::Message,
            ])]),
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::Message,
                        ThreadTest::Message,
                        ThreadTest::Message,
                        ThreadTest::Message,
                    ]),
                    ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::Message,
                                        ThreadTest::Message,
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                        ]),
                                    ]),
                                    ThreadTest::Message,
                                ],
                            )]),
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![
                                    ThreadTest::Message,
                                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                                ],
                            )]),
                        ]),
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::Message,
                        ]),
                    ])]),
                    ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                    ThreadTest::Message,
                ]),
                ThreadTest::MessageWithReplies(vec![ThreadTest::Message]),
                ThreadTest::Message,
            ]),
        ]),
        ThreadTest::MessageWithReplies(vec![
            ThreadTest::Message,
            ThreadTest::MessageWithReplies(vec![
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::MessageWithReplies(vec![
                                ThreadTest::MessageWithReplies(vec![
                                    ThreadTest::MessageWithReplies(vec![
                                        ThreadTest::MessageWithReplies(vec![
                                            ThreadTest::Message,
                                            ThreadTest::Message,
                                            ThreadTest::MessageWithReplies(vec![
                                                ThreadTest::Message,
                                                ThreadTest::Message,
                                            ]),
                                        ]),
                                        ThreadTest::Message,
                                    ]),
                                    ThreadTest::Message,
                                    ThreadTest::Message,
                                ]),
                                ThreadTest::Message,
                                ThreadTest::Message,
                                ThreadTest::Message,
                            ]),
                            ThreadTest::Message,
                        ]),
                        ThreadTest::Message,
                    ]),
                    ThreadTest::Message,
                ]),
                ThreadTest::MessageWithReplies(vec![
                    ThreadTest::Message,
                    ThreadTest::MessageWithReplies(vec![
                        ThreadTest::Message,
                        ThreadTest::Message,
                        ThreadTest::MessageWithReplies(vec![
                            ThreadTest::Message,
                            ThreadTest::MessageWithReplies(vec![ThreadTest::MessageWithReplies(
                                vec![ThreadTest::Message, ThreadTest::Message],
                            )]),
                            ThreadTest::Message,
                        ]),
                        ThreadTest::Message,
                    ]),
                ]),
            ]),
        ]),
    ])
}
