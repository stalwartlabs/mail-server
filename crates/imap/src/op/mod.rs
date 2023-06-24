use imap_proto::StatusResponse;

pub mod authenticate;
pub mod create;
pub mod delete;
pub mod list;
pub mod rename;
pub mod status;
pub mod subscribe;

pub type Result<T> = std::result::Result<T, StatusResponse>;
