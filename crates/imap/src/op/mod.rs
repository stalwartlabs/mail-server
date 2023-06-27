use ::store::query::log::Query;
use imap_proto::StatusResponse;

pub mod append;
pub mod authenticate;
pub mod close;
pub mod copy_move;
pub mod create;
pub mod delete;
pub mod enable;
pub mod expunge;
pub mod fetch;
pub mod list;
pub mod login;
pub mod logout;
pub mod namespace;
pub mod rename;
pub mod select;
pub mod status;
pub mod store;
pub mod subscribe;

trait FromModSeq {
    fn from_modseq(modseq: u64) -> Self;
}

impl FromModSeq for Query {
    fn from_modseq(modseq: u64) -> Self {
        if modseq > 0 {
            Query::Since(modseq - 1)
        } else {
            Query::All
        }
    }
}

pub type Result<T> = std::result::Result<T, StatusResponse>;
