/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::LegacyBincode;
use common::Server;
use smtp::queue::{
    Domain, ErrorDetails, HostResponse, Message, QueueId, QuotaKey, Recipient, Status,
};
use store::{
    IterateParams, Serialize, U64_LEN, ValueKey,
    ahash::AHashSet,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, QueueClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use utils::BlobHash;

pub(crate) async fn migrate_queue(server: &Server) -> trc::Result<()> {
    let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
        store::write::QueueEvent {
            due: 0,
            queue_id: 0,
        },
    )));
    let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
        store::write::QueueEvent {
            due: u64::MAX,
            queue_id: u64::MAX,
        },
    )));

    let mut queue_ids = AHashSet::new();
    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                queue_ids.insert(key.deserialize_be_u64(U64_LEN)?);

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(0)));
    let to_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX)));
    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                queue_ids.insert(key.deserialize_be_u64(0)?);

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut count = 0;

    for queue_id in queue_ids {
        match server
            .store()
            .get_value::<LegacyBincode<LegacyMessage>>(ValueKey::from(ValueClass::Queue(
                QueueClass::Message(queue_id),
            )))
            .await
        {
            Ok(Some(bincoded)) => {
                let message = bincoded.inner;
                let message = Message {
                    queue_id: message.queue_id,
                    created: message.created,
                    blob_hash: message.blob_hash,
                    return_path: message.return_path,
                    return_path_lcase: message.return_path_lcase,
                    return_path_domain: message.return_path_domain,
                    recipients: message
                        .recipients
                        .into_iter()
                        .map(|r| Recipient {
                            domain_idx: r.domain_idx as u32,
                            address: r.address,
                            address_lcase: r.address_lcase,
                            status: r.status,
                            flags: r.flags,
                            orcpt: r.orcpt,
                        })
                        .collect(),
                    domains: message.domains,
                    flags: message.flags,
                    env_id: message.env_id,
                    priority: message.priority,
                    size: message.size as u64,
                    quota_keys: message.quota_keys,
                    span_id: message.span_id,
                };

                let mut batch = BatchBuilder::new();
                batch.set(
                    ValueClass::Queue(QueueClass::Message(queue_id)),
                    Archiver::new(message)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
                count += 1;
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            Ok(None) => (),
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                        QueueClass::Message(queue_id),
                    )))
                    .await
                    .is_err()
                {
                    return Err(err
                        .ctx(trc::Key::QueueId, queue_id)
                        .caused_by(trc::location!()));
                }
            }
        }
    }

    if count > 0 {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Migrated {count} queued messages",)
        );
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct LegacyMessage {
    pub queue_id: QueueId,
    pub created: u64,
    pub blob_hash: BlobHash,

    pub return_path: String,
    pub return_path_lcase: String,
    pub return_path_domain: String,
    pub recipients: Vec<LegacyRecipient>,
    pub domains: Vec<Domain>,

    pub flags: u64,
    pub env_id: Option<String>,
    pub priority: i16,

    pub size: usize,
    pub quota_keys: Vec<QuotaKey>,

    #[serde(skip)]
    pub span_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct LegacyRecipient {
    pub domain_idx: usize,
    pub address: String,
    pub address_lcase: String,
    pub status: Status<HostResponse<String>, HostResponse<ErrorDetails>>,
    pub flags: u64,
    pub orcpt: Option<String>,
}
