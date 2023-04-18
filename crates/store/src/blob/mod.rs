//pub mod purge;
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
            config.value_require("blob.store.path")?.into(),
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
