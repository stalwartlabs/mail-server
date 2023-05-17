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

use ahash::AHashSet;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};
use utils::ipc::DeliveryEvent;

use self::cache::LookupCache;

pub mod cache;
pub mod dispatch;
pub mod imap;
pub mod smtp;
pub mod spawn;
pub mod sql;

#[derive(Debug)]
pub enum Lookup {
    List(AHashSet<String>),
    Remote(LookupChannel),
    Sql(SqlQuery),
    #[cfg(feature = "local_delivery")]
    Local(mpsc::Sender<DeliveryEvent>),
}

#[derive(Debug, Clone)]
pub enum SqlDatabase {
    Postgres(sqlx::Pool<sqlx::Postgres>),
    MySql(sqlx::Pool<sqlx::MySql>),
    //MsSql(sqlx::Pool<sqlx::Mssql>),
    SqlLite(sqlx::Pool<sqlx::Sqlite>),
}

#[derive(Debug)]
pub struct SqlQuery {
    pub query: String,
    pub db: SqlDatabase,
    pub cache: Option<Mutex<LookupCache<String>>>,
}

impl Default for Lookup {
    fn default() -> Self {
        Lookup::List(AHashSet::default())
    }
}

#[derive(Debug)]
pub enum Event {
    Lookup(utils::ipc::LookupItem),
    WorkerReady {
        item: utils::ipc::Item,
        result: Option<bool>,
        next_lookup: Option<oneshot::Sender<Option<utils::ipc::LookupItem>>>,
    },
    WorkerFailed,
    Reload,
    Stop,
}

#[derive(Debug, Clone)]
pub struct LookupChannel {
    pub tx: mpsc::Sender<Event>,
}

#[derive(Clone)]
struct NextHop<T: RemoteLookup> {
    tx: mpsc::Sender<Event>,
    host: T,
}

pub trait RemoteLookup: Clone {
    fn spawn_lookup(&self, lookup: utils::ipc::LookupItem, tx: mpsc::Sender<Event>);
}
