/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use directory::{backend::internal::manage::ManageDirectory, Directory, Type};
use sieve::Sieve;
use store::{
    write::{QueueClass, ValueClass},
    BlobStore, FtsStore, IterateParams, LookupStore, Store, ValueKey,
};
use trc::AddContext;

use crate::{
    config::smtp::{
        auth::{ArcSealer, DkimSigner},
        queue::RelayHost,
    },
    ImapId, Inner, MailboxState, Server,
};

impl Server {
    #[inline(always)]
    pub fn store(&self) -> &Store {
        &self.core.storage.data
    }

    #[inline(always)]
    pub fn blob_store(&self) -> &BlobStore {
        &self.core.storage.blob
    }

    #[inline(always)]
    pub fn fts_store(&self) -> &FtsStore {
        &self.core.storage.fts
    }

    #[inline(always)]
    pub fn lookup_store(&self) -> &LookupStore {
        &self.core.storage.lookup
    }

    #[inline(always)]
    pub fn directory(&self) -> &Directory {
        &self.core.storage.directory
    }

    pub fn get_directory(&self, name: &str) -> Option<&Arc<Directory>> {
        self.core.storage.directories.get(name)
    }

    pub fn get_directory_or_default(&self, name: &str, session_id: u64) -> &Arc<Directory> {
        self.core.storage.directories.get(name).unwrap_or_else(|| {
            if !name.is_empty() {
                trc::event!(
                    Eval(trc::EvalEvent::DirectoryNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );
            }

            &self.core.storage.directory
        })
    }

    pub fn get_lookup_store(&self, name: &str, session_id: u64) -> &LookupStore {
        self.core.storage.lookups.get(name).unwrap_or_else(|| {
            if !name.is_empty() {
                trc::event!(
                    Eval(trc::EvalEvent::StoreNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );
            }

            &self.core.storage.lookup
        })
    }

    pub fn get_arc_sealer(&self, name: &str, session_id: u64) -> Option<&ArcSealer> {
        self.core
            .smtp
            .mail_auth
            .sealers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                trc::event!(
                    Arc(trc::ArcEvent::SealerNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );

                None
            })
    }

    pub fn get_dkim_signer(&self, name: &str, session_id: u64) -> Option<&DkimSigner> {
        self.core
            .smtp
            .mail_auth
            .signers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                trc::event!(
                    Dkim(trc::DkimEvent::SignerNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );

                None
            })
    }

    pub fn get_trusted_sieve_script(&self, name: &str, session_id: u64) -> Option<&Arc<Sieve>> {
        self.core.sieve.trusted_scripts.get(name).or_else(|| {
            trc::event!(
                Sieve(trc::SieveEvent::ScriptNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub fn get_untrusted_sieve_script(&self, name: &str, session_id: u64) -> Option<&Arc<Sieve>> {
        self.core.sieve.untrusted_scripts.get(name).or_else(|| {
            trc::event!(
                Sieve(trc::SieveEvent::ScriptNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub fn get_relay_host(&self, name: &str, session_id: u64) -> Option<&RelayHost> {
        self.core.smtp.queue.relay_hosts.get(name).or_else(|| {
            trc::event!(
                Smtp(trc::SmtpEvent::RemoteIdNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub async fn total_queued_messages(&self) -> trc::Result<u64> {
        let mut total = 0;
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Queue(QueueClass::Message(0))),
                    ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX))),
                )
                .no_values(),
                |_, _| {
                    total += 1;

                    Ok(true)
                },
            )
            .await
            .map(|_| total)
    }

    pub async fn total_accounts(&self) -> trc::Result<u64> {
        self.store()
            .count_principals(None, Type::Individual.into(), None)
            .await
            .caused_by(trc::location!())
    }

    pub async fn total_domains(&self) -> trc::Result<u64> {
        self.store()
            .count_principals(None, Type::Domain.into(), None)
            .await
            .caused_by(trc::location!())
    }
}

pub trait BuildServer {
    fn build_server(&self) -> Server;
}

impl BuildServer for Arc<Inner> {
    fn build_server(&self) -> Server {
        Server {
            inner: self.clone(),
            core: self.shared_core.load_full(),
        }
    }
}

impl MailboxState {
    pub fn map_result_id(&self, document_id: u32, is_uid: bool) -> Option<(u32, ImapId)> {
        if let Some(imap_id) = self.id_to_imap.get(&document_id) {
            Some((if is_uid { imap_id.uid } else { imap_id.seqnum }, *imap_id))
        } else if is_uid {
            self.next_state.as_ref().and_then(|s| {
                s.next_state
                    .id_to_imap
                    .get(&document_id)
                    .map(|imap_id| (imap_id.uid, *imap_id))
            })
        } else {
            None
        }
    }
}
