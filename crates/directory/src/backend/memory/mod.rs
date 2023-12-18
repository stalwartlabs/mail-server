/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use ahash::{AHashMap, AHashSet};
use store::Store;
use tokio::sync::oneshot;

use crate::Principal;

use super::internal::manage::ManageDirectory;

pub mod config;
pub mod lookup;

#[derive(Default, Debug)]
pub struct MemoryDirectory {
    principals: Vec<Principal<u32>>,
    emails_to_ids: AHashMap<String, Vec<EmailType>>,
    names_to_ids: NameToId,
    domains: AHashSet<String>,
}

pub enum NameToId {
    Internal(AHashMap<String, u32>),
    Store(Store),
}

impl Default for NameToId {
    fn default() -> Self {
        Self::Internal(AHashMap::new())
    }
}

impl std::fmt::Debug for NameToId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(arg0) => f.debug_tuple("Internal").field(arg0).finish(),
            Self::Store(_) => f.debug_tuple("Store").finish(),
        }
    }
}

impl From<Option<Store>> for NameToId {
    fn from(store: Option<Store>) -> Self {
        match store {
            Some(store) => Self::Store(store),
            None => Self::Internal(AHashMap::new()),
        }
    }
}

impl NameToId {
    pub fn get_or_insert(&mut self, name: &str) -> crate::Result<u32> {
        match self {
            Self::Internal(map) => {
                let next_id = map.len() as u32;
                Ok(*map.entry(name.to_string()).or_insert(next_id))
            }
            Self::Store(store) => {
                let (tx, rx) = oneshot::channel();
                let store = store.clone();
                let name = name.to_string();
                tokio::spawn(async move {
                    let _ = tx.send(store.get_or_create_account_id(&name).await);
                });
                match rx.blocking_recv() {
                    Ok(result) => result,
                    Err(_) => Err(crate::DirectoryError::Unsupported),
                }
            }
        }
    }
}

#[derive(Debug)]
enum EmailType {
    Primary(u32),
    Alias(u32),
    List(u32),
}
