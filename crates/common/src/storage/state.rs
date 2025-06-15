/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::{state::StateChange, type_state::DataType};
use tokio::sync::mpsc;
use utils::map::bitmap::Bitmap;

use crate::{IPC_CHANNEL_BUFFER, Server, ipc::StateEvent};

impl Server {
    pub async fn subscribe_state_manager(
        &self,
        account_id: u32,
        types: Bitmap<DataType>,
    ) -> trc::Result<mpsc::Receiver<StateChange>> {
        let (change_tx, change_rx) = mpsc::channel::<StateChange>(IPC_CHANNEL_BUFFER);
        let state_tx = self.inner.ipc.state_tx.clone();

        for event in [
            StateEvent::UpdateSharedAccounts { account_id },
            StateEvent::Subscribe {
                account_id,
                types,
                tx: change_tx,
            },
        ] {
            state_tx.send(event).await.map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .caused_by(trc::location!())
            })?;
        }

        Ok(change_rx)
    }
}
