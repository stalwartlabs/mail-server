/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use mail_send::Credentials;
use tokio::sync::{mpsc, oneshot};
use utils::ipc::{DeliveryEvent, Item, LookupItem, LookupResult};

use super::Lookup;

impl Lookup {
    pub async fn contains(&self, entry: &str) -> Option<bool> {
        match self {
            #[cfg(feature = "local_delivery")]
            Lookup::Local(tx) => lookup_local(tx, Item::IsAccount(entry.to_string()))
                .await
                .map(|r| r.into()),
            Lookup::Remote(tx) => tx
                .lookup(Item::IsAccount(entry.to_string()))
                .await
                .map(|r| r.into()),
            Lookup::Sql(sql) => sql.exists(entry).await,
            Lookup::List(entries) => Some(entries.contains(entry)),
        }
    }

    pub async fn lookup(&self, item: Item) -> Option<LookupResult> {
        match self {
            #[cfg(feature = "local_delivery")]
            Lookup::Local(tx) => lookup_local(tx, item).await,

            Lookup::Remote(tx) => tx.lookup(item).await,

            Lookup::Sql(sql) => match item {
                Item::IsAccount(account) => sql.exists(&account).await.map(LookupResult::from),
                Item::Authenticate(credentials) => match credentials {
                    Credentials::Plain { username, secret }
                    | Credentials::XOauth2 { username, secret } => sql
                        .fetch_one(&username)
                        .await
                        .map(|pwd| LookupResult::from(pwd.map_or(false, |pwd| pwd == secret))),
                    Credentials::OAuthBearer { token } => {
                        sql.exists(&token).await.map(LookupResult::from)
                    }
                },
                Item::Verify(account) => sql.fetch_many(&account).await.map(LookupResult::from),
                Item::Expand(list) => sql.fetch_many(&list).await.map(LookupResult::from),
            },

            Lookup::List(list) => match item {
                Item::IsAccount(item) => Some(list.contains(&item).into()),
                Item::Verify(_item) | Item::Expand(_item) => {
                    #[cfg(feature = "test_mode")]
                    for list_item in list {
                        if let Some((prefix, suffix)) = list_item.split_once(':') {
                            if prefix == _item {
                                return Some(LookupResult::Values(
                                    suffix.split(',').map(|i| i.to_string()).collect::<Vec<_>>(),
                                ));
                            }
                        }
                    }
                    Some(LookupResult::False)
                }
                Item::Authenticate(credentials) => {
                    let entry = match credentials {
                        Credentials::Plain { username, secret }
                        | Credentials::XOauth2 { username, secret } => {
                            format!("{username}:{secret}")
                        }
                        Credentials::OAuthBearer { token } => token,
                    };

                    if !list.is_empty() {
                        Some(list.contains(&entry).into())
                    } else {
                        None
                    }
                }
            },
        }
    }
}

async fn lookup_local(
    delivery_tx: &mpsc::Sender<DeliveryEvent>,
    item: Item,
) -> Option<LookupResult> {
    let (tx, rx) = oneshot::channel();
    if delivery_tx
        .send(DeliveryEvent::Lookup(LookupItem { item, result: tx }))
        .await
        .is_ok()
    {
        rx.await.ok()
    } else {
        None
    }
}
