use jmap_proto::types::{blob::BlobId, id::Id};

pub mod download;
pub mod upload;

#[derive(Debug, serde::Serialize)]
pub struct UploadResponse {
    #[serde(rename(serialize = "accountId"))]
    account_id: Id,
    #[serde(rename(serialize = "blobId"))]
    blob_id: BlobId,
    #[serde(rename(serialize = "type"))]
    c_type: String,
    size: usize,
}

pub struct DownloadResponse {
    pub filename: String,
    pub content_type: String,
    pub blob: Vec<u8>,
}
