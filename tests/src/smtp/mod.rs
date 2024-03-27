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

use std::{path::PathBuf, sync::Arc};

use common::Core;

use smtp::core::{Inner, SMTP};
use store::{BlobStore, Store};
use tokio::sync::mpsc;

pub mod config;
pub mod inbound;
pub mod lookup;
pub mod management;
pub mod outbound;
pub mod queue;
pub mod reporting;
pub mod session;

pub struct TempDir {
    pub temp_dir: PathBuf,
    pub delete: bool,
}

impl TempDir {
    pub fn new(name: &str, delete: bool) -> TempDir {
        let mut temp_dir = std::env::temp_dir();
        temp_dir.push(name);
        if !temp_dir.exists() {
            let _ = std::fs::create_dir(&temp_dir);
        } else if delete {
            let _ = std::fs::remove_dir_all(&temp_dir);
            let _ = std::fs::create_dir(&temp_dir);
        }
        TempDir { temp_dir, delete }
    }

    pub fn update_config(&self, config: impl AsRef<str>) -> String {
        config
            .as_ref()
            .replace("{TMP}", self.temp_dir.to_str().unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.delete {
            let _ = std::fs::remove_dir_all(&self.temp_dir);
        }
    }
}

pub fn add_test_certs(config: &str) -> String {
    let mut cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cert_path.push("resources");
    cert_path.push("smtp");
    cert_path.push("certs");
    let mut cert = cert_path.clone();
    cert.push("tls_cert.pem");
    let mut pk = cert_path.clone();
    pk.push("tls_privatekey.pem");

    config
        .replace("{CERT}", cert.as_path().to_str().unwrap())
        .replace("{PK}", pk.as_path().to_str().unwrap())
}

pub struct QueueReceiver {
    store: Store,
    blob_store: BlobStore,
    pub queue_rx: mpsc::Receiver<smtp::queue::Event>,
}

pub struct ReportReceiver {
    pub report_rx: mpsc::Receiver<smtp::reporting::Event>,
}

pub trait TestSMTP {
    fn init_test_queue(&mut self, core: &Core) -> QueueReceiver;
    fn init_test_report(&mut self) -> ReportReceiver;
}

impl TestSMTP for Inner {
    fn init_test_queue(&mut self, core: &Core) -> QueueReceiver {
        let (queue_tx, queue_rx) = mpsc::channel(128);
        self.queue_tx = queue_tx;

        QueueReceiver {
            blob_store: core.storage.blob.clone(),
            store: core.storage.data.clone(),
            queue_rx,
        }
    }

    fn init_test_report(&mut self) -> ReportReceiver {
        let (report_tx, report_rx) = mpsc::channel(128);
        self.report_tx = report_tx;
        ReportReceiver { report_rx }
    }
}

fn build_smtp(core: impl Into<Arc<Core>>, inner: impl Into<Arc<Inner>>) -> SMTP {
    SMTP {
        core: core.into(),
        inner: inner.into(),
    }
}
