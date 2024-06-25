/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::{HashMap, HashSet},
    io::{self, Cursor},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use console::style;
use futures::{stream::FuturesUnordered, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use jmap_client::{
    core::set::SetObject,
    mailbox::{self, Role},
};
use mail_parser::mailbox::{
    maildir,
    mbox::{self, MessageIterator},
};
use rand::Rng;
use serde::de::DeserializeOwned;
use tokio::{fs::File, io::AsyncReadExt};

use crate::modules::{name_to_id, UnwrapResult, RETRY_ATTEMPTS};

use super::{
    cli::{Client, ImportCommands, MailboxFormat},
    export::{
        fetch_emails, fetch_identities, fetch_mailboxes, fetch_sieve_scripts,
        fetch_vacation_responses,
    },
    read_file,
};

enum Mailbox {
    Mbox(mbox::MessageIterator<Cursor<Vec<u8>>>),
    Maildir(maildir::MessageIterator),
    None,
}

#[derive(Debug)]
enum MailboxId<'x> {
    ExistingId(&'x str),
    CreateId(String),
    None,
}

#[derive(Debug)]
struct Message {
    identifier: String,
    flags: Vec<maildir::Flag>,
    internal_date: u64,
    contents: Vec<u8>,
}
impl ImportCommands {
    pub async fn exec(self, client: Client) {
        let mut client = client.into_jmap_client().await;

        match self {
            ImportCommands::Messages {
                num_concurrent,
                format,
                account,
                path,
            } => {
                client.set_default_account_id(name_to_id(&client, &account).await);
                let mut create_mailboxes = Vec::new();
                let mut create_mailbox_names = Vec::new();
                let mut create_mailbox_ids = Vec::new();

                eprintln!("{} Parsing mailbox...", style("[1/4]").bold().dim(),);

                match format {
                    MailboxFormat::Mbox => {
                        create_mailbox_names.push(Vec::new());
                        create_mailboxes.push(Mailbox::Mbox(MessageIterator::new(Cursor::new(
                            read_file(&path),
                        ))));
                    }
                    MailboxFormat::Maildir | MailboxFormat::MaildirNested => {
                        let (folder_sep, folder_split) = if format == MailboxFormat::Maildir {
                            (Some("."), ".")
                        } else {
                            (None, "/")
                        };

                        for folder in maildir::FolderIterator::new(path, folder_sep)
                            .unwrap_result("read Maildir folder")
                        {
                            let folder = folder.unwrap_result("read Maildir folder");
                            if let Some(folder_name) = folder.name() {
                                let mut folder_parts = Vec::new();
                                for folder_name in folder_name.split(folder_split) {
                                    let mut folder_name = folder_name.trim();
                                    if folder_name.is_empty() {
                                        folder_name = ".";
                                    }
                                    folder_parts.push(folder_name.to_string());
                                    if !create_mailbox_names.contains(&folder_parts) {
                                        create_mailboxes.push(Mailbox::None);
                                        create_mailbox_names.push(folder_parts.clone());
                                    }
                                }

                                *create_mailboxes.last_mut().unwrap() = Mailbox::Maildir(folder);
                            } else {
                                create_mailboxes.push(Mailbox::Maildir(folder));
                                create_mailbox_names.push(Vec::new());
                            };
                        }
                    }
                }

                // Fetch all mailboxes for the account
                eprintln!(
                    "{} Fetching existing mailboxes for account...",
                    style("[2/4]").bold().dim(),
                );

                let mut inbox_id = None;
                let mut mailbox_ids = HashMap::new();
                let mut children: HashMap<Option<&str>, Vec<&str>> =
                    HashMap::from_iter([(None, Vec::new())]);
                let mut request = client.build();
                request.get_mailbox().properties([
                    mailbox::Property::Name,
                    mailbox::Property::ParentId,
                    mailbox::Property::Role,
                    mailbox::Property::Id,
                ]);
                let response = request
                    .send_get_mailbox()
                    .await
                    .unwrap_result("fetch mailboxes");
                for mailbox in response.list() {
                    let mailbox_id = mailbox.id().unwrap();
                    if mailbox.role() == Role::Inbox {
                        inbox_id = mailbox_id.into();
                    }
                    children
                        .entry(mailbox.parent_id())
                        .or_default()
                        .push(mailbox_id);
                    mailbox_ids.insert(mailbox_id, mailbox.name().unwrap_or("Untitled"));
                }
                let inbox_id = inbox_id
                    .unwrap_result("locate Inbox on account, please check the server logs.");
                let mut it = children.get(&None).unwrap().iter();
                let mut it_stack = Vec::new();
                let mut name_stack = Vec::new();
                let mut mailbox_names = HashMap::with_capacity(mailbox_ids.len());

                // Build mailbox hierarchy on the server
                eprintln!(
                    "{} Creating missing mailboxes...",
                    style("[3/4]").bold().dim(),
                );

                loop {
                    while let Some(mailbox_id) = it.next() {
                        let name = mailbox_ids[mailbox_id];
                        let mut mailbox_name = name_stack.clone();
                        mailbox_name.push(name.to_string());

                        mailbox_names.insert(mailbox_name, mailbox_id);
                        if let Some(next_it) = children.get(&Some(mailbox_id)).map(|c| c.iter()) {
                            name_stack.push(name.to_string());
                            it_stack.push(it);
                            it = next_it;
                        }
                    }

                    if let Some(prev_it) = it_stack.pop() {
                        name_stack.pop();
                        it = prev_it;
                    } else {
                        break;
                    }
                }

                // Check whether the mailboxes to be created already exist
                let mut has_missing_mailboxes = false;
                for mailbox_name in &create_mailbox_names {
                    create_mailbox_ids.push(if !mailbox_name.is_empty() {
                        if let Some(mailbox_id) = mailbox_names.get(mailbox_name) {
                            MailboxId::ExistingId(mailbox_id)
                        } else {
                            has_missing_mailboxes = true;
                            MailboxId::None
                        }
                    } else {
                        MailboxId::ExistingId(inbox_id)
                    });
                }

                // Create any missing mailboxes
                if has_missing_mailboxes {
                    let mut request = client.build();
                    let set_request = request.set_mailbox();

                    for pos in 0..create_mailbox_ids.len() {
                        if let MailboxId::None = create_mailbox_ids[pos] {
                            let mailbox_name = &create_mailbox_names[pos];
                            let create_request =
                                set_request.create().name(mailbox_name.last().unwrap());

                            if mailbox_name.len() > 1 {
                                let parent_mailbox_name = &mailbox_name[..mailbox_name.len() - 1];
                                let parent_mailbox_pos = create_mailbox_names
                                    .iter()
                                    .position(|n| n == parent_mailbox_name)
                                    .unwrap();
                                match &create_mailbox_ids[parent_mailbox_pos] {
                                    MailboxId::ExistingId(id) => {
                                        create_request.parent_id((*id).into());
                                    }
                                    MailboxId::CreateId(id_ref) => {
                                        create_request.parent_id_ref(id_ref);
                                    }
                                    MailboxId::None => unreachable!(),
                                }
                            } else {
                                create_request.parent_id(None::<String>);
                            }
                            create_mailbox_ids[pos] =
                                MailboxId::CreateId(create_request.create_id().unwrap());
                        }
                    }

                    // Create mailboxes
                    let mut response = request
                        .send_set_mailbox()
                        .await
                        .unwrap_result("create mailboxes");
                    for create_mailbox_id in create_mailbox_ids.iter_mut() {
                        if let MailboxId::CreateId(id) = create_mailbox_id {
                            *id = response
                                .created(id)
                                .unwrap_result("create mailbox")
                                .take_id();
                        }
                    }
                }

                // Import messages
                eprintln!("{} Importing messages...", style("[4/4]").bold().dim(),);

                let client = Arc::new(client);
                let total_imported = Arc::new(AtomicUsize::from(0));
                let m = MultiProgress::new();
                let num_concurrent = num_concurrent.unwrap_or_else(num_cpus::get);
                let spinner_style =
                    ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")
                        .unwrap()
                        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
                let pbs = Arc::new(Mutex::new((
                    (0..num_concurrent)
                        .map(|n| {
                            let pb = m.add(ProgressBar::new(40));
                            pb.set_style(spinner_style.clone());
                            pb.set_prefix(format!("[{}/?]", n + 1));
                            pb
                        })
                        .collect::<Vec<_>>(),
                    0usize,
                )));
                let failures = Arc::new(Mutex::new(Vec::new()));
                let mut message_num = 0;

                for ((mut mailbox, mailbox_id), mailbox_name) in create_mailboxes
                    .into_iter()
                    .zip(create_mailbox_ids)
                    .zip(create_mailbox_names)
                {
                    let mut futures = FuturesUnordered::new();
                    let mailbox_id = Arc::new(match mailbox_id {
                        MailboxId::ExistingId(id) => id.to_string(),
                        MailboxId::CreateId(id) => id,
                        MailboxId::None => unreachable!(),
                    });
                    let mailbox_name = Arc::new(if !mailbox_name.is_empty() {
                        mailbox_name.join("/")
                    } else {
                        "Inbox".to_string()
                    });

                    for result in mailbox.by_ref() {
                        match result {
                            Ok(message) => {
                                message_num += 1;
                                let client = client.clone();
                                let mailbox_id = mailbox_id.clone();
                                let mailbox_name = mailbox_name.clone();
                                let total_imported = total_imported.clone();
                                let pbs = pbs.clone();
                                let failures = failures.clone();

                                futures.push(async move {
                                    // Update progress bar
                                    {
                                        let mut pbs = pbs.lock().unwrap();
                                        let pb = &pbs.0[pbs.1 % pbs.0.len()];
                                        pb.set_message(format!(
                                            "Importing {}: {}/{}",
                                            message_num, mailbox_name, message.identifier
                                        ));
                                        pb.inc(1);
                                        pbs.1 += 1;
                                    }

                                    let mut retry_count = 0;
                                    loop {
                                        // Sanitize message
                                        let mut contents =
                                            Vec::with_capacity(message.contents.len());
                                        let mut last_ch = 0;
                                        for &ch in message.contents.iter() {
                                            if ch == b'\n' && last_ch != b'\r' {
                                                contents.push(b'\r');
                                            }
                                            contents.push(ch);
                                            last_ch = ch;
                                        }

                                        match client
                                            .email_import(
                                                contents,
                                                [mailbox_id.as_ref()],
                                                if !message.flags.is_empty() {
                                                    message
                                                        .flags
                                                        .iter()
                                                        .map(|f| match f {
                                                            maildir::Flag::Passed => "$passed",
                                                            maildir::Flag::Replied => "$answered",
                                                            maildir::Flag::Seen => "$seen",
                                                            maildir::Flag::Trashed => "$deleted",
                                                            maildir::Flag::Draft => "$draft",
                                                            maildir::Flag::Flagged => "$flagged",
                                                        })
                                                        .into()
                                                } else {
                                                    None
                                                },
                                                if message.internal_date > 0 {
                                                    (message.internal_date as i64).into()
                                                } else {
                                                    None
                                                },
                                            )
                                            .await
                                        {
                                            Ok(_) => {
                                                total_imported.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) if retry_count < RETRY_ATTEMPTS => {
                                                let backoff =
                                                    rand::thread_rng().gen_range(50..=300);
                                                tokio::time::sleep(Duration::from_millis(backoff))
                                                    .await;
                                                retry_count += 1;
                                                continue;
                                            }
                                            Err(err) => {
                                                failures.lock().unwrap().push(format!(
                                                    concat!(
                                                        "Failed to import message {} ",
                                                        "with identifier '{}': {}"
                                                    ),
                                                    message_num, message.identifier, err
                                                ));
                                            }
                                        }
                                        break;
                                    }
                                });

                                if futures.len() == num_concurrent {
                                    futures.next().await.unwrap();
                                }
                            }
                            Err(e) => {
                                failures
                                    .lock()
                                    .unwrap()
                                    .push(format!("I/O error reading message: {}", e));
                            }
                        }
                    }

                    // Wait for remaining futures
                    while futures.next().await.is_some() {}
                }

                // Done
                for pb in pbs.lock().unwrap().0.iter() {
                    pb.finish_with_message("Done");
                }
                let failures = failures.lock().unwrap();
                eprintln!(
                    "\n\nSuccessfully imported {} messages.\n",
                    total_imported.load(Ordering::Relaxed)
                );

                if !failures.is_empty() {
                    eprintln!("There were {} failures:\n", failures.len());
                    for failure in failures.iter() {
                        eprintln!("{}", failure);
                    }
                }
            }

            ImportCommands::Account {
                num_concurrent,
                account,
                path,
            } => {
                client.set_default_account_id(name_to_id(&client, &account).await);
                let path = PathBuf::from(path);
                if !path.exists() {
                    eprintln!("Path '{}' does not exist.", path.display());
                    return;
                }
                let num_concurrent = num_concurrent.unwrap_or_else(num_cpus::get);

                // Import objects
                import_emails(
                    &client,
                    &path,
                    import_mailboxes(&client, &path).await.into(),
                    num_concurrent,
                )
                .await;
                import_sieve_scripts(&client, &path, num_concurrent).await;
                import_identities(&client, &path).await;
                import_vacation_responses(&client, &path).await;
            }
        }
    }
}

async fn import_mailboxes(
    client: &jmap_client::client::Client,
    path: &Path,
) -> HashMap<String, String> {
    // Deserialize mailboxes
    let mailboxes = read_json::<jmap_client::mailbox::Mailbox>(path, "mailboxes.json").await;
    if mailboxes.is_empty() {
        return HashMap::new();
    }

    // Obtain current mailboxes
    let existing_mailboxes = fetch_mailboxes(
        client,
        client
            .session()
            .core_capabilities()
            .map(|c| c.max_objects_in_get())
            .unwrap_or(500),
    )
    .await;
    let nested_existing_mailboxes = build_mailbox_tree(&existing_mailboxes);
    let mut id_mappings: HashMap<String, String> = HashMap::new();
    let mut id_missing = Vec::new();
    for (path, mailbox) in build_mailbox_tree(&mailboxes) {
        let id = mailbox.id().unwrap_result("obtain mailbox id");
        // Find existing mailbox based on role
        if !matches!(mailbox.role(), Role::None) {
            if let Some(existing_mailbox) = existing_mailboxes
                .iter()
                .find(|m| m.role() == mailbox.role())
            {
                id_mappings.insert(
                    id.to_string(),
                    existing_mailbox
                        .id()
                        .unwrap_result("obtain mailbox id")
                        .to_string(),
                );
                continue;
            }
        }

        // Find existing mailbox by name
        if let Some(mailbox) = nested_existing_mailboxes.get(&path) {
            id_mappings.insert(
                id.to_string(),
                mailbox.id().unwrap_result("obtain mailbox id").to_string(),
            );
        } else {
            id_missing.push(id);
        }
    }
    let mut total_imported = 0;
    let mut total_existing = 0;
    if !id_missing.is_empty() {
        let mut request = client.build();
        let set_request = request.set_mailbox();

        for mailbox in &mailboxes {
            // Skip if mailbox already exists
            let id = mailbox.id().unwrap_result("obtain mailbox id").to_string();
            if id_mappings.contains_key(&id) {
                total_existing += 1;
                continue;
            }
            let create_request = set_request
                .create_with_id(&id)
                .name(mailbox.name().unwrap())
                .role(mailbox.role());
            if let Some(parent_id) = mailbox.parent_id() {
                if let Some(existing_id) = id_mappings.get(parent_id) {
                    create_request.parent_id(Some(existing_id.to_string()));
                } else {
                    create_request.parent_id_ref(parent_id);
                }
            } else {
                create_request.parent_id(None::<String>);
            }
            if mailbox.sort_order() > 0 {
                create_request.sort_order(mailbox.sort_order());
            }
            if let Some(acls) = mailbox.acl() {
                create_request.acls(acls.clone().into_iter());
            }
            if mailbox.is_subscribed() {
                create_request.is_subscribed(true);
            }
        }

        // Create mailboxes
        let mut response = request
            .send_set_mailbox()
            .await
            .unwrap_result("create mailboxes");
        for missing_id in id_missing {
            id_mappings.insert(
                missing_id.to_string(),
                response
                    .created(missing_id)
                    .unwrap_result("create mailbox")
                    .take_id(),
            );
            total_imported += 1;
        }
    } else {
        total_existing = mailboxes.len();
    }

    eprintln!(
        "Successfully processed {} mailboxes ({} imported, {} already exist).",
        total_existing + total_imported,
        total_imported,
        total_existing
    );

    id_mappings
}

async fn import_emails(
    client: &jmap_client::client::Client,
    path: &Path,
    mailbox_ids: Arc<HashMap<String, String>>,
    num_concurrent: usize,
) {
    // Deserialize emails
    let emails = read_json::<jmap_client::email::Email>(path, "emails.json").await;
    if emails.is_empty() {
        return;
    }

    // Obtain existing emails
    let existing_emails = fetch_emails(
        client,
        client
            .session()
            .core_capabilities()
            .map(|c| c.max_objects_in_get())
            .unwrap_or(500),
    )
    .await;
    let existing_ids = existing_emails
        .iter()
        .map(|email| (email.message_id(), email.received_at()))
        .collect::<HashSet<_>>();
    let mut futures = FuturesUnordered::new();
    let total_imported = Arc::new(AtomicUsize::from(0));
    let mut total_existing = 0;
    let mut path = PathBuf::from(path);
    path.push("blobs");

    for email in emails {
        // Skip messages that already exist in the server
        if existing_ids.contains(&(email.message_id(), email.received_at())) {
            total_existing += 1;
            continue;
        }

        // Spawn import tasks
        let mailbox_ids = mailbox_ids.clone();
        let mut path = path.clone();
        let total_imported = total_imported.clone();

        futures.push(async move {
            // Obtain mailbox ids
            let id = if let Some(id) = email.id() {
                id
            } else {
                eprintln!("Skipping email with no id");
                return;
            };
            if email.mailbox_ids().is_empty() {
                eprintln!("Skipping emailId {id} with no mailboxIds");
                return;
            }
            let mut mailboxes = Vec::with_capacity(email.mailbox_ids().len());
            for mailbox_id in email.mailbox_ids() {
                if let Some(mailbox_id) = mailbox_ids.get(mailbox_id) {
                    mailboxes.push(mailbox_id.to_string());
                } else {
                    eprintln!("Skipping emailId {id} with unknown mailboxId {mailbox_id}");
                    return;
                }
            }
            let keywords = email.keywords();

            // Read blob
            if let Some(blob_id) = email.blob_id() {
                path.push(blob_id);
            } else {
                eprintln!("Skipping emailId {id} with no blobId");
                return;
            }
            let mut contents = vec![];
            match File::open(&path).await {
                Ok(mut file) => match file.read_to_end(&mut contents).await {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!(
                            "Failed to read blob file for emailId {id} at {path:?}: {err}",
                            id = id,
                            path = path,
                            err = err
                        );
                        return;
                    }
                },
                Err(err) => {
                    eprintln!(
                        "Failed to open blob file for emailId {id} at {path:?}: {err}",
                        id = id,
                        path = path,
                        err = err
                    );
                    return;
                }
            }

            let mut retry_count = 0;
            loop {
                match client
                    .email_import(
                        contents.clone(),
                        mailboxes.clone(),
                        if !keywords.is_empty() {
                            Some(keywords.clone())
                        } else {
                            None
                        },
                        email.received_at(),
                    )
                    .await
                {
                    Ok(_) => {
                        total_imported.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) if retry_count < RETRY_ATTEMPTS => {
                        retry_count += 1;
                        continue;
                    }
                    Err(err) => {
                        eprintln!("Failed to import emailId {id}: {err}");
                    }
                }
                break;
            }
        });

        if futures.len() == num_concurrent {
            futures.next().await.unwrap();
        }
    }

    // Wait for remaining futures
    while futures.next().await.is_some() {}

    // Done
    eprintln!(
        "Successfully processed {} emails ({} imported, {} already exist).",
        total_imported.load(Ordering::Relaxed) + total_existing,
        total_imported.load(Ordering::Relaxed),
        total_existing
    );
}

async fn import_sieve_scripts(
    client: &jmap_client::client::Client,
    path: &Path,
    num_concurrent: usize,
) {
    // Deserialize scripts
    let scripts = read_json::<jmap_client::sieve::SieveScript>(path, "sieve.json").await;
    if scripts.is_empty() {
        return;
    }
    let existing_scripts = fetch_sieve_scripts(
        client,
        client
            .session()
            .core_capabilities()
            .map(|c| c.max_objects_in_get())
            .unwrap_or(500),
    )
    .await;
    let mut path = PathBuf::from(path);
    path.push("blobs");

    // Spawn tasks
    let mut futures = FuturesUnordered::new();
    let total_imported = Arc::new(AtomicUsize::from(0));
    let mut total_existing = 0;

    'outer: for script in scripts {
        // Skip scripts that already exist
        for existing_script in &existing_scripts {
            if existing_script.name() == script.name() {
                total_existing += 1;
                continue 'outer;
            }
        }
        let mut path = path.clone();
        let total_imported = total_imported.clone();

        futures.push(async move {
            let id = if let Some(id) = script.id() {
                id
            } else {
                eprintln!("Skipping script with no id.");
                return;
            };

            // Read blob
            let name = if let (Some(blob_id), Some(name)) = (script.blob_id(), script.name()) {
                path.push(blob_id);
                name
            } else {
                eprintln!("Skipping script {id} with no blobId and/or name");
                return;
            };
            let mut contents = vec![];
            match File::open(&path).await {
                Ok(mut file) => match file.read_to_end(&mut contents).await {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!(
                            "Failed to read blob file for script {id} at {path:?}: {err}",
                            id = id,
                            path = path,
                            err = err
                        );
                        return;
                    }
                },
                Err(err) => {
                    eprintln!(
                        "Failed to open blob file for script {id} at {path:?}: {err}",
                        id = id,
                        path = path,
                        err = err
                    );
                    return;
                }
            }

            // Upload blob
            match client
                .sieve_script_create(name, contents, script.is_active())
                .await
            {
                Ok(_) => {
                    total_imported.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    eprintln!("Failed to import script {id}: {err}");
                }
            }
        });

        if futures.len() == num_concurrent {
            futures.next().await.unwrap();
        }
    }

    // Wait for remaining futures
    while futures.next().await.is_some() {}

    // Done
    eprintln!(
        "Successfully processed {} sieve scripts ({} imported, {} already exist).",
        total_imported.load(Ordering::Relaxed) + total_existing,
        total_imported.load(Ordering::Relaxed),
        total_existing
    );
}

async fn import_identities(client: &jmap_client::client::Client, path: &Path) {
    // Deserialize mailboxes
    let identities = read_json::<jmap_client::identity::Identity>(path, "identities.json").await;
    if identities.is_empty() {
        return;
    }
    let existing_identities = fetch_identities(client).await;
    let mut request = client.build();
    let set_request = request.set_identity();
    let mut create_ids = Vec::new();
    let mut total_existing = 0;

    'outer: for identity in &identities {
        for existing_identity in &existing_identities {
            if identity.name() == existing_identity.name()
                && identity.email() == existing_identity.email()
            {
                total_existing += 1;
                continue 'outer;
            }
        }

        if let (Some(id), Some(name), Some(email)) =
            (identity.id(), identity.name(), identity.email())
        {
            if name != "vacation" {
                create_ids.push(id);
                let create_request = set_request.create_with_id(id).name(name).email(email);
                if let Some(reply_to) = identity.reply_to() {
                    create_request.reply_to(reply_to.iter().cloned().into());
                }
                if let Some(bcc) = identity.bcc() {
                    create_request.bcc(bcc.iter().cloned().into());
                }
                if let Some(html_signature) = identity.html_signature() {
                    create_request.html_signature(html_signature);
                }
                if let Some(text_signature) = identity.text_signature() {
                    create_request.text_signature(text_signature);
                }
            }
        } else {
            eprintln!("Skipping identity with no id, name, and/or email.");
            continue;
        }
    }

    let mut total_imported = 0;
    if !create_ids.is_empty() {
        match request.send_set_identity().await {
            Ok(mut response) => {
                for id in create_ids {
                    if let Err(err) = response.created(id) {
                        eprintln!("Failed to import identity {id}: {err}");
                    } else {
                        total_imported += 1;
                    }
                }
            }
            Err(err) => {
                eprintln!("Failed to import identities: {err}");
                return;
            }
        }
    }

    eprintln!(
        "Successfully processed {} identities ({} imported, {} already exist).",
        total_imported + total_existing,
        total_imported,
        total_existing
    );
}

async fn import_vacation_responses(client: &jmap_client::client::Client, path: &Path) {
    // Deserialize mailboxes
    let vacation_responses =
        read_json::<jmap_client::vacation_response::VacationResponse>(path, "vacation.json").await;
    if vacation_responses.is_empty() {
        return;
    }
    let existing_vacation_responses = fetch_vacation_responses(client).await;
    if !existing_vacation_responses.is_empty() {
        eprintln!("Successfully processed 1 vacation response (0 imported, 1 already exist).",);
        return;
    }

    let vacation_response = vacation_responses.into_iter().next().unwrap();
    let mut request = client.build();
    let set_request = request.set_vacation_response().create();

    if vacation_response.is_enabled() {
        set_request.is_enabled(true);
    }
    if let Some(from_date) = vacation_response.from_date() {
        set_request.from_date(from_date.into());
    }
    if let Some(to_date) = vacation_response.to_date() {
        set_request.to_date(to_date.into());
    }
    if let Some(subject) = vacation_response.subject() {
        set_request.subject(subject.into());
    }
    if let Some(text_body) = vacation_response.text_body() {
        set_request.text_body(text_body.into());
    }
    if let Some(html_body) = vacation_response.html_body() {
        set_request.html_body(html_body.into());
    }
    let create_id = set_request.create_id().unwrap();

    match request.send_set_vacation_response().await {
        Ok(mut response) => {
            if let Err(err) = response.created(&create_id) {
                eprintln!("Failed to import vacation response: {err}");
            } else {
                eprintln!(
                    "Successfully processed 1 vacation response (1 imported, 0 already exist).",
                );
            }
        }
        Err(err) => {
            eprintln!("Failed to import vacation response: {err}");
        }
    }
}

fn build_mailbox_tree(
    mailboxes: &[jmap_client::mailbox::Mailbox],
) -> HashMap<Vec<&str>, &jmap_client::mailbox::Mailbox> {
    let mut path = Vec::new();
    let mut parent_id = None;
    let mut mailboxes_iter = mailboxes.iter();
    let mut stack = Vec::new();
    let mut results = HashMap::with_capacity(mailboxes.len());
    let parents = mailboxes
        .iter()
        .map(|m| m.parent_id())
        .collect::<HashSet<_>>();

    'outer: loop {
        while let Some(mailbox) = mailboxes_iter.next() {
            if parent_id == mailbox.parent_id() {
                let name = mailbox.name().unwrap_result("obtain mailbox name");
                if parents.contains(&mailbox.id()) {
                    stack.push((path.clone(), parent_id, mailboxes_iter));
                    parent_id = mailbox.id();
                    path.push(name);
                    results.insert(path.clone(), mailbox);
                    mailboxes_iter = mailboxes.iter();
                    continue 'outer;
                } else {
                    let mut path = path.clone();
                    path.push(name);
                    results.insert(path, mailbox);
                }
            }
        }
        if let Some((prev_path, prev_parent_id, prev_iter)) = stack.pop() {
            parent_id = prev_parent_id;
            path = prev_path;
            mailboxes_iter = prev_iter;
        } else {
            break;
        }
    }
    debug_assert_eq!(results.len(), mailboxes.len());

    results
}

async fn read_json<T: DeserializeOwned>(path: &Path, filename: &str) -> Vec<T> {
    let mut path = PathBuf::from(path);
    path.push(filename);
    if path.exists() {
        let mut file = File::open(path).await.unwrap_result("open file");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .await
            .unwrap_result("read file");
        serde_json::from_str(&contents).unwrap_result("parse JSON")
    } else {
        Vec::new()
    }
}

impl Iterator for Mailbox {
    type Item = io::Result<Message>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Mailbox::Mbox(it) => it.next().map(|r| {
                r.map(|m| Message {
                    identifier: m.from().to_string(),
                    flags: Vec::new(),
                    internal_date: m.internal_date(),
                    contents: m.unwrap_contents(),
                })
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "Failed to parse from mbox file.")
                })
            }),
            Mailbox::Maildir(it) => it.next().map(|r| {
                r.map(|m| Message {
                    identifier: m
                        .path()
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    flags: m.flags().to_vec(),
                    internal_date: m.internal_date(),
                    contents: m.unwrap_contents(),
                })
            }),
            Mailbox::None => None,
        }
    }
}
