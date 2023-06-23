use imap_proto::StatusResponse;

pub mod authenticate;
//pub mod create;
pub mod list;
pub mod status;

pub type Result<T> = std::result::Result<T, StatusResponse>;
