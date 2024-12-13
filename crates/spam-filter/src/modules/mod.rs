use common::Server;
use store::{Deserialize, Value};

pub mod dnsbl;
pub mod html;
pub mod pyzor;
pub mod remote_list;
pub mod sanitize;

pub(crate) async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
    server: &Server,
    span_id: u64,
    key: impl Into<Vec<u8>>,
) -> Result<Option<T>, ()> {
    server
        .lookup_store()
        .key_get(key.into())
        .await
        .map_err(|err| {
            trc::error!(err.span_id(span_id).caused_by(trc::location!()));
        })
}

pub(crate) async fn key_set(
    server: &Server,
    span_id: u64,
    key: Vec<u8>,
    value: Vec<u8>,
    expires: Option<u64>,
) {
    if let Err(err) = server.lookup_store().key_set(key, value, expires).await {
        trc::error!(err.span_id(span_id).caused_by(trc::location!()));
    }
}
