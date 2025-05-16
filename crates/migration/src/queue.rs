/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::LegacyBincode;
use common::Server;
use smtp::queue::Message;
use store::{
    IterateParams, Serialize, U64_LEN, ValueKey,
    ahash::AHashSet,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, QueueClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;

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

    let count = queue_ids.len();

    for queue_id in queue_ids {
        match server
            .store()
            .get_value::<LegacyBincode<Message>>(ValueKey::from(ValueClass::Queue(
                QueueClass::Message(queue_id),
            )))
            .await
        {
            Ok(Some(bincoded)) => {
                let mut batch = BatchBuilder::new();
                batch.set(
                    ValueClass::Queue(QueueClass::Message(queue_id)),
                    Archiver::new(bincoded.inner)
                        .serialize()
                        .caused_by(trc::location!())?,
                );

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
