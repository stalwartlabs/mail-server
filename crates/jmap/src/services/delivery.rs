use std::sync::Arc;

use mail_send::Credentials;
use tokio::sync::mpsc;
use utils::ipc::{DeliveryEvent, Item};

use crate::JMAP;

pub fn spawn_delivery_manager(core: Arc<JMAP>, mut delivery_rx: mpsc::Receiver<DeliveryEvent>) {
    tokio::spawn(async move {
        while let Some(event) = delivery_rx.recv().await {
            match event {
                DeliveryEvent::Ingest { message, result_tx } => {
                    result_tx.send(core.deliver_message(message).await).ok();
                }
                DeliveryEvent::Lookup(lookup) => {
                    lookup
                        .result
                        .send(match lookup.item {
                            Item::IsAccount(address) => {
                                (!core.get_uids_by_address(&address).await.is_empty()).into()
                            }
                            Item::Authenticate(credentials) => match credentials {
                                Credentials::Plain { username, secret } => {
                                    core.authenticate(&username, &secret).await.is_some()
                                }
                                _ => false,
                            }
                            .into(),
                            Item::Verify(address) => core.vrfy_address(&address).await.into(),
                            Item::Expand(address) => core.expn_address(&address).await.into(),
                        })
                        .ok();
                }
                DeliveryEvent::Stop => break,
            }
        }
    });
}
