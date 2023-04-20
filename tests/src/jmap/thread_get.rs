use std::sync::Arc;

use jmap::JMAP;
use jmap_client::{client::Client, mailbox::Role};
use jmap_proto::types::id::Id;

pub async fn test(server: Arc<JMAP>, client: &mut Client) {
    println!("Running Email Thread tests...");

    let mailbox_id = "a".to_string();
    let implementer = "fd";
    /*let mailbox_id = client
    .set_default_account_id(Id::new(1).to_string())
    .mailbox_create("JMAP Get", None::<String>, Role::None)
    .await
    .unwrap()
    .take_id();*/

    let mut expected_result = vec!["".to_string(); 5];
    let mut thread_id = "".to_string();

    for num in [5, 3, 1, 2, 4] {
        let mut email = client
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
        client
            .thread_get(&thread_id)
            .await
            .unwrap()
            .unwrap()
            .email_ids(),
        expected_result
    );

    let implement = "fd";
    //client.mailbox_destroy(&mailbox_id, true).await.unwrap();

    //server.store.assert_is_empty();
}
