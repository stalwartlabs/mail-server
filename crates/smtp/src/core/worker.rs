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

use std::sync::atomic::Ordering;

use tokio::sync::oneshot;

use super::SMTP;

impl SMTP {
    pub async fn spawn_worker<U, V>(&self, f: U) -> Option<V>
    where
        U: FnOnce() -> V + Send + 'static,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.inner.worker_pool.spawn(move || {
            tx.send(f()).ok();
        });

        match rx.await {
            Ok(result) => Some(result),
            Err(err) => {
                tracing::warn!(
                    context = "worker-pool",
                    event = "error",
                    reason = %err,
                );
                None
            }
        }
    }

    fn cleanup(&self) {
        for throttle in [&self.inner.session_throttle, &self.inner.queue_throttle] {
            throttle.retain(|_, v| v.concurrent.load(Ordering::Relaxed) > 0);
        }
    }

    pub fn spawn_cleanup(&self) {
        let core = self.clone();
        self.inner.worker_pool.spawn(move || {
            core.cleanup();
        });
    }
}
