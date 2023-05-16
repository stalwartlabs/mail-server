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
use mail_send::Credentials;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use self::cache::LookupCache;

pub mod cache;
pub mod dispatch;
pub mod imap;
pub mod smtp;
pub mod spawn;
pub mod sql;

#[derive(Debug)]
pub enum Lookup {
    Local(AHashSet<String>),
    Remote(LookupChannel),
    Sql(SqlQuery),
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
        Lookup::Local(AHashSet::default())
    }
}

#[derive(Debug)]
pub enum Event {
    Lookup(LookupItem),
    WorkerReady {
        item: Item,
        result: Option<bool>,
        next_lookup: Option<oneshot::Sender<Option<LookupItem>>>,
    },
    WorkerFailed,
    Reload,
    Stop,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Item {
    IsAccount(String),
    Authenticate(Credentials<String>),
    Verify(String),
    Expand(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    True,
    False,
    Values(Vec<String>),
}

#[derive(Debug)]
pub struct LookupItem {
    pub item: Item,
    pub result: oneshot::Sender<LookupResult>,
}

#[derive(Debug, Clone)]
pub struct LookupChannel {
    pub tx: mpsc::Sender<Event>,
}

#[derive(Clone)]
struct RemoteHost<T: RemoteLookup> {
    tx: mpsc::Sender<Event>,
    host: T,
}

pub trait RemoteLookup: Clone {
    fn spawn_lookup(&self, lookup: LookupItem, tx: mpsc::Sender<Event>);
}
