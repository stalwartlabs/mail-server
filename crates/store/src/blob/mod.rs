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

use std::{path::PathBuf, time::Duration};

use s3::{
    creds::{error::CredentialsError, Credentials},
    error::S3Error,
    Bucket, Region,
};
use utils::config::Config;

use crate::BlobKind;

pub enum BlobStore {
    Local(BlobPaths),
    Remote(Bucket),
}

pub struct BlobPaths {
    path_email: PathBuf,
    path_temporary: PathBuf,
    path_other: PathBuf,
}

impl BlobStore {
    pub async fn new(config: &Config) -> crate::Result<Self> {
        match config.value_require("store.blob.type")? {
            "s3" | "minio" | "gcs" => {
                // Obtain region and endpoint from config
                let region = config.value_require("store.blob.s3.region")?;
                let region = if let Some(endpoint) = config.value("store.blob.s3.endpoint") {
                    Region::Custom {
                        region: region.to_string(),
                        endpoint: endpoint.to_string(),
                    }
                } else {
                    region.parse().unwrap()
                };
                let credentials = Credentials::new(
                    config.value("store.blob.s3.access-key"),
                    config.value("store.blob.s3.secret-key"),
                    config.value("store.blob.s3.security-token"),
                    config.value("store.blob.s3.session-token"),
                    config.value("store.blob.s3.profile"),
                )?;
                let timeout =
                    config.property_or_static::<Duration>("store.blob.s3.timeout", "30s")?;

                Ok(BlobStore::Remote(
                    Bucket::new(
                        config.value_require("store.blob.s3.bucket")?,
                        region,
                        credentials,
                    )?
                    .with_path_style()
                    .with_request_timeout(timeout),
                ))
            }
            "local" => {
                let path = config.property_require::<PathBuf>("store.blob.local.path")?;
                let mut path_email = path.clone();
                path_email.push("emails");
                let mut path_temporary = path.clone();
                path_temporary.push("tmp");
                let mut path_other = path;
                path_other.push("blobs");

                Ok(BlobStore::Local(BlobPaths {
                    path_email,
                    path_temporary,
                    path_other,
                }))
            }
            unknown => Err(crate::Error::InternalError(format!(
                "Unknown blob store type: {unknown}",
            ))),
        }
    }
}

impl From<std::io::Error> for crate::Error {
    fn from(err: std::io::Error) -> Self {
        Self::InternalError(format!("IO error: {}", err))
    }
}

impl From<S3Error> for crate::Error {
    fn from(err: S3Error) -> Self {
        Self::InternalError(format!("S3 error: {}", err))
    }
}

impl From<CredentialsError> for crate::Error {
    fn from(err: CredentialsError) -> Self {
        Self::InternalError(format!("S3 Credentials error: {}", err))
    }
}

fn get_local_path(base_path: &BlobPaths, kind: &BlobKind) -> PathBuf {
    match kind {
        BlobKind::LinkedMaildir {
            account_id,
            document_id,
        } => {
            let mut path = base_path.path_email.to_path_buf();
            path.push(format!("{:x}", account_id));
            path.push("Maildir");
            path.push("cur");
            path.push(format!("{:x}", document_id));
            path
        }
        BlobKind::Linked {
            account_id,
            collection,
            document_id,
        } => {
            let mut path = base_path.path_other.to_path_buf();
            path.push(format!("{:x}", account_id));
            path.push(format!("{:x}", collection));
            path.push(format!("{:x}", document_id));
            path
        }
        BlobKind::Temporary {
            account_id,
            creation_year,
            creation_month,
            creation_day,
            seq,
        } => {
            let mut path = base_path.path_temporary.to_path_buf();
            path.push(creation_year.to_string());
            path.push(creation_month.to_string());
            path.push(creation_day.to_string());
            path.push(format!("{:x}_{:x}", account_id, seq));
            path
        }
    }
}

fn get_local_root_path(base_path: &BlobPaths, kind: &BlobKind) -> PathBuf {
    match kind {
        BlobKind::LinkedMaildir { account_id, .. } => {
            let mut path = base_path.path_email.to_path_buf();
            path.push(format!("{:x}", account_id));
            path
        }
        BlobKind::Linked { account_id, .. } => {
            let mut path = base_path.path_other.to_path_buf();
            path.push(format!("{:x}", account_id));
            path
        }
        BlobKind::Temporary {
            creation_year,
            creation_month,
            creation_day,
            ..
        } => {
            let mut path = base_path.path_temporary.to_path_buf();
            path.push(creation_year.to_string());
            path.push(creation_month.to_string());
            path.push(creation_day.to_string());
            path
        }
    }
}

fn get_s3_path(kind: &BlobKind) -> String {
    match kind {
        BlobKind::LinkedMaildir {
            account_id,
            document_id,
        } => format!("/{:x}/{:x}", account_id, document_id),
        BlobKind::Linked {
            account_id,
            collection,
            document_id,
        } => format!("/{:x}/{:x}/{:x}", account_id, collection, document_id),
        BlobKind::Temporary {
            account_id,
            creation_year,
            creation_month,
            creation_day,
            seq,
        } => format!(
            "/tmp/{}/{}/{}/{:x}_{:x}",
            creation_year, creation_month, creation_day, account_id, seq
        ),
    }
}

fn get_s3_root_path(kind: &BlobKind) -> String {
    match kind {
        BlobKind::LinkedMaildir { account_id, .. } => {
            format!("/{:x}/", account_id)
        }
        BlobKind::Linked { account_id, .. } => {
            format!("/{:x}/", account_id)
        }
        BlobKind::Temporary {
            creation_year,
            creation_month,
            creation_day,
            ..
        } => format!(
            "/tmp/{}/{}/{}/",
            creation_year, creation_month, creation_day
        ),
    }
}
