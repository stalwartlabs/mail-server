/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use core::hash::Hash;
use std::hash::Hasher;

use ahash::AHasher;
use tokio::sync::{Mutex, MutexGuard};

pub struct MutexMap<T: Default> {
    map: Box<[Mutex<T>]>,
    mask: u64,
    hasher: AHasher,
}

pub struct MutexMapLockError;
pub type Result<T> = std::result::Result<T, MutexMapLockError>;

#[allow(clippy::mutex_atomic)]
impl<T: Default> MutexMap<T> {
    pub fn with_capacity(size: usize) -> MutexMap<T> {
        let size = size.next_power_of_two();
        MutexMap {
            map: (0..size)
                .map(|_| T::default().into())
                .collect::<Vec<Mutex<T>>>()
                .into_boxed_slice(),
            mask: (size - 1) as u64,
            hasher: AHasher::default(),
        }
    }

    pub async fn lock<U>(&self, key: U) -> MutexGuard<'_, T>
    where
        U: Into<u64> + Copy,
    {
        let hash = key.into() & self.mask;
        self.map[hash as usize].lock().await
    }

    /*pub async fn try_lock<U>(&self, key: U, timeout: Duration) -> Option<MutexGuard<'_, T>>
    where
        U: Into<u64> + Copy,
    {
        let hash = key.into() & self.mask;
        self.map[hash as usize].try_lock(timeout).await
    }*/

    pub async fn lock_hash<U>(&self, key: U) -> MutexGuard<'_, T>
    where
        U: Hash,
    {
        let mut hasher = self.hasher.clone();
        key.hash(&mut hasher);
        let hash = hasher.finish() & self.mask;
        self.map[hash as usize].lock().await
    }

    /*pub async fn try_lock_hash<U>(&self, key: U, timeout: Duration) -> Option<MutexGuard<'_, T>>
    where
        U: Hash,
    {
        let mut hasher = self.hasher.clone();
        key.hash(&mut hasher);
        let hash = hasher.finish() & self.mask;
        self.map[hash as usize].try_lock_for(timeout).await
    }*/
}
