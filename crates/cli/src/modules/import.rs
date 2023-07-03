/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Command Line Interface.
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
    collections::HashMap,
    io::{self, Cursor},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use console::style;
use futures::{stream::FuturesUnordered, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use jmap_client::{
    client::Client,
    core::set::SetObject,
    mailbox::{self, Role},
};
use mail_parser::mailbox::{
    maildir,
    mbox::{self, MessageIterator},
};

use crate::modules::UnwrapResult;

use super::{
    cli::{ImportCommands, MailboxFormat},
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

pub async fn cmd_import(client: Client, command: ImportCommands) {
    match command {
        ImportCommands::Messages {
            num_threads,
            format,
            account_id,
            path,
        } => {
            let account_id = Arc::new(account_id);
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
            request
                .get_mailbox()
                .account_id(account_id.as_ref())
                .properties([
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
                    .or_insert_with(Vec::new)
                    .push(mailbox_id);
                mailbox_ids.insert(mailbox_id, mailbox.name().unwrap_or("Untitled"));
            }
            let inbox_id =
                inbox_id.unwrap_result("locate Inbox on account, please check the server logs.");
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
                let set_request = request.set_mailbox().account_id(account_id.as_ref());

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
            let num_threads = num_threads.unwrap_or_else(|| num_cpus::get());
            let spinner_style =
                ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")
                    .unwrap()
                    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
            let pbs = Arc::new(Mutex::new((
                (0..num_threads)
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
                let mut outputs = Vec::new();
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

                while let Some(result) = mailbox.next() {
                    match result {
                        Ok(message) => {
                            message_num += 1;
                            let client = client.clone();
                            let account_id = account_id.clone();
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

                                if let Err(err) = client
                                    .email_import_account(
                                        &account_id,
                                        message.contents,
                                        [mailbox_id.as_ref()],
                                        if !message.flags.is_empty() {
                                            message
                                                .flags
                                                .into_iter()
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
                                    failures.lock().unwrap().push(format!(
                                        concat!(
                                            "Failed to import message {} ",
                                            "with identifier '{}': {}"
                                        ),
                                        message_num, message.identifier, err
                                    ));
                                } else {
                                    total_imported.fetch_add(1, Ordering::Relaxed);
                                }
                            });

                            if futures.len() == num_threads {
                                outputs.push(futures.next().await.unwrap());
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
                while let Some(item) = futures.next().await {
                    outputs.push(item);
                }
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
