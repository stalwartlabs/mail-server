use std::sync::Arc;

use crate::core::IMAP;

use directory::DirectoryConfig;
use imap_proto::{protocol::capability::Capability, ResponseCode, StatusResponse};
use utils::config::Config;

pub mod core;

static SERVER_GREETING: &str = concat!(
    "Stalwart IMAP4rev2 v",
    env!("CARGO_PKG_VERSION"),
    " at your service."
);

impl IMAP {
    pub async fn init(config: &Config, directory: &DirectoryConfig) -> Result<Arc<Self>, String> {
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
            greeting_plain: StatusResponse::ok(SERVER_GREETING)
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(false, false),
                })
                .into_bytes(),
            timeout_auth: config.property_or_static("imap.timeout.authenticated", "30m")?,
            timeout_unauth: config.property_or_static("imap.timeout.anonymous", "1m")?,
            greeting_tls: StatusResponse::ok(SERVER_GREETING)
                .with_code(ResponseCode::Capability {
                    capabilities: Capability::all_capabilities(false, true),
                })
                .into_bytes(),
        }))
    }
}
