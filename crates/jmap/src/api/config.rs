use std::time::Duration;

use store::{
    fts::Language,
    rand::{distributions::Alphanumeric, thread_rng, Rng},
};

use super::session::BaseCapabilities;

impl crate::Config {
    pub fn new(settings: &utils::config::Config) -> Result<Self, String> {
        let mut config = Self {
            default_language: Language::from_iso_639(
                settings.value("jmap.fts.default-language").unwrap_or("en"),
            )
            .unwrap_or(Language::English),
            query_max_results: settings
                .property("jmap.protocol.query.max-results")?
                .unwrap_or(5000),
            changes_max_results: settings
                .property("jmap.protocol.changes.max-results")?
                .unwrap_or(5000),
            request_max_size: settings
                .property("jmap.protocol.request.max-size")?
                .unwrap_or(10000000),
            request_max_calls: settings
                .property("jmap.protocol.request.max-calls")?
                .unwrap_or(16),
            request_max_concurrent: settings
                .property("jmap.protocol.request.max-concurrent")?
                .unwrap_or(4),
            get_max_objects: settings
                .property("jmap.protocol.get.max-objects")?
                .unwrap_or(500),
            set_max_objects: settings
                .property("jmap.protocol.set.max-objects")?
                .unwrap_or(500),
            upload_max_size: settings
                .property("jmap.protocol.upload.max-size")?
                .unwrap_or(50000000),
            upload_max_concurrent: settings
                .property("jmap.protocol.upload.max-concurrent")?
                .unwrap_or(4),
            mailbox_max_depth: settings.property("jmap.mailbox.max-depth")?.unwrap_or(10),
            mailbox_name_max_len: settings
                .property("jmap.mailbox.max-name-length")?
                .unwrap_or(255),
            mail_attachments_max_size: settings
                .property("jmap.email.max-attachment-size")?
                .unwrap_or(50000000),
            mail_max_size: settings
                .property("jmap.email.max-size")?
                .unwrap_or(75000000),
            mail_parse_max_items: settings
                .property("jmap.email.parse.max-items")?
                .unwrap_or(50000000),
            sieve_max_script_name: settings
                .property("jmap.sieve.max-name-length")?
                .unwrap_or(512),
            sieve_max_scripts: settings
                .property("jmap.protocol.max-scripts")?
                .unwrap_or(256),
            capabilities: BaseCapabilities::default(),
            session_cache_ttl: settings
                .property("jmap.session.cache.ttl")?
                .unwrap_or(Duration::from_secs(3600)),
            rate_authenticated: settings
                .property_or_static("jmap.rate-limit.account.rate", "1000/1m")?,
            rate_authenticate_req: settings
                .property_or_static("jmap.rate-limit.authentication.rate", "10/1m")?,
            rate_anonymous: settings
                .property_or_static("jmap.rate-limit.anonymous.rate", "100/1m")?,
            rate_use_forwarded: settings
                .property("jmap.rate-limit.use-forwarded")?
                .unwrap_or(false),
            oauth_key: settings
                .value("oauth.key")
                .map(|k| k.into())
                .unwrap_or_else(|| {
                    thread_rng()
                        .sample_iter(Alphanumeric)
                        .take(64)
                        .map(char::from)
                        .collect::<String>()
                }),
            oauth_expiry_user_code: settings
                .property_or_static::<Duration>("oauth.expiry.user-code", "30m")?
                .as_secs(),
            oauth_expiry_auth_code: settings
                .property_or_static::<Duration>("oauth.expiry.auth-code", "10m")?
                .as_secs(),
            oauth_expiry_token: settings
                .property_or_static::<Duration>("oauth.expiry.token", "1h")?
                .as_secs(),
            oauth_expiry_refresh_token: settings
                .property_or_static::<Duration>("oauth.expiry.refresh-token", "30d")?
                .as_secs(),
            oauth_expiry_refresh_token_renew: settings
                .property_or_static::<Duration>("oauth.expiry.refresh-token-renew", "4d")?
                .as_secs(),
            oauth_max_auth_attempts: settings.property_or_static("oauth.max-auth-attempts", "3")?,
            event_source_throttle: settings
                .property_or_static("jmap.event-source.throttle", "1s")?,
            web_socket_throttle: settings.property_or_static("jmap.web-socket.throttle", "1s")?,
            web_socket_timeout: settings.property_or_static("jmap.web-socket.timeout", "10m")?,
            web_socket_heartbeat: settings.property_or_static("jmap.web-socket.heartbeat", "1m")?,
            push_max_total: settings.property_or_static("jmap.push.max-total", "100")?,
        };
        config.add_capabilites(settings);
        Ok(config)
    }
}
