/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

pub mod read;
pub mod write;

use std::path::{Path, PathBuf};

use utils::config::Config;

use crate::BlobKind;

pub enum BlobStore {
    Local(PathBuf),
    Remote(String),
}

impl BlobStore {
    pub async fn new(config: &Config) -> crate::Result<Self> {
        Ok(BlobStore::Local(
            config.value_require("store.blob.path")?.into(),
        ))
    }
}

impl From<std::io::Error> for crate::Error {
    fn from(err: std::io::Error) -> Self {
        Self::InternalError(format!("IO error: {}", err))
    }
}

fn get_path(base_path: &Path, kind: &BlobKind) -> crate::Result<PathBuf> {
    let mut path = base_path.to_path_buf();
    match kind {
        BlobKind::Linked {
            account_id,
            collection,
            document_id,
        } => {
            path.push(format!("{:x}", account_id));
            path.push(format!("{:x}", collection));
            path.push(format!("{:x}", document_id));
        }
        BlobKind::LinkedMaildir {
            account_id,
            document_id,
        } => {
            path.push(format!("{:x}", account_id));
            path.push("Maildir");
            path.push("cur");
            path.push(format!("{:x}", document_id));
        }
        BlobKind::Temporary {
            account_id,
            creation_year,
            creation_month,
            creation_day,
            seq,
        } => {
            path.push("tmp");
            path.push(creation_year.to_string());
            path.push(creation_month.to_string());
            path.push(creation_day.to_string());
            path.push(format!("{:x}_{:x}", account_id, seq));
        }
    }

    Ok(path)
}

fn get_root_path(base_path: &Path, kind: &BlobKind) -> crate::Result<PathBuf> {
    let mut path = base_path.to_path_buf();
    match kind {
        BlobKind::Linked { account_id, .. } | BlobKind::LinkedMaildir { account_id, .. } => {
            path.push(format!("{:x}", account_id));
        }
        BlobKind::Temporary {
            creation_year,
            creation_month,
            creation_day,
            ..
        } => {
            path.push("tmp");
            path.push(creation_year.to_string());
            path.push(creation_month.to_string());
            path.push(creation_day.to_string());
        }
    }

    Ok(path)
}
