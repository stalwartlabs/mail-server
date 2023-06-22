use std::sync::Arc;

use crate::core::IMAP;

use imap_proto::{protocol::capability::Capability, ResponseCode, StatusResponse};
use utils::config::Config;

pub mod core;
pub mod op;

static SERVER_GREETING: &str = concat!(
    "Stalwart IMAP4rev2 v",
    env!("CARGO_PKG_VERSION"),
    " at your service."
);

impl IMAP {
    pub async fn init(config: &Config) -> utils::config::Result<Arc<Self>> {
        Ok(Arc::new(IMAP {
            max_request_size: config.property_or_static("imap.request.max-size", "52428800")?,
            name_shared: config
                .value("imap.folders.name.shared")
                .unwrap_or("Shared Folders")
                .to_string(),
            name_all: config
                .value("imap.folders.name.all")
                .unwrap_or("All Mail")
                .to_string(),
            timeout_auth: config.property_or_static("imap.timeout.authenticated", "30m")?,
            timeout_unauth: config.property_or_static("imap.timeout.anonymous", "1m")?,
            greeting_plain: StatusResponse::ok(SERVER_GREETING)
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(false, false),
                })
                .into_bytes(),
            greeting_tls: StatusResponse::ok(SERVER_GREETING)
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(false, true),
                })
                .into_bytes(),
        }))
    }
}

pub struct ImapError;

pub type Result<T> = std::result::Result<T, ()>;
pub type OpResult = std::result::Result<(), ()>;
