use std::{str::FromStr, time::Duration};

use jmap_proto::request::capability::BaseCapabilities;
use mail_parser::HeaderName;
use nlp::language::Language;
use store::rand::{distributions::Alphanumeric, thread_rng, Rng};
use utils::config::{cron::SimpleCron, utils::ParseValue, Config, Rate};

#[derive(Default, Clone)]
pub struct JmapConfig {
    pub default_language: Language,
    pub query_max_results: usize,
    pub snippet_max_results: usize,

    pub changes_max_results: usize,
    pub changes_max_history: Option<Duration>,

    pub request_max_size: usize,
    pub request_max_calls: usize,
    pub request_max_concurrent: u64,

    pub get_max_objects: usize,
    pub set_max_objects: usize,

    pub upload_max_size: usize,
    pub upload_max_concurrent: u64,

    pub upload_tmp_quota_size: usize,
    pub upload_tmp_quota_amount: usize,
    pub upload_tmp_ttl: u64,

    pub mailbox_max_depth: usize,
    pub mailbox_name_max_len: usize,
    pub mail_attachments_max_size: usize,
    pub mail_parse_max_items: usize,
    pub mail_max_size: usize,
    pub mail_autoexpunge_after: Option<Duration>,

    pub sieve_max_script_name: usize,
    pub sieve_max_scripts: usize,

    pub session_cache_ttl: Duration,
    pub rate_authenticated: Option<Rate>,
    pub rate_authenticate_req: Option<Rate>,
    pub rate_anonymous: Option<Rate>,

    pub event_source_throttle: Duration,
    pub push_max_total: usize,
    pub push_attempt_interval: Duration,
    pub push_attempts_max: u32,
    pub push_retry_interval: Duration,
    pub push_timeout: Duration,
    pub push_verify_timeout: Duration,
    pub push_throttle: Duration,

    pub web_socket_throttle: Duration,
    pub web_socket_timeout: Duration,
    pub web_socket_heartbeat: Duration,

    pub oauth_key: String,
    pub oauth_expiry_user_code: u64,
    pub oauth_expiry_auth_code: u64,
    pub oauth_expiry_token: u64,
    pub oauth_expiry_refresh_token: u64,
    pub oauth_expiry_refresh_token_renew: u64,
    pub oauth_max_auth_attempts: u32,
    pub fallback_admin: Option<(String, String)>,
    pub master_user: Option<(String, String)>,

    pub spam_header: Option<(HeaderName<'static>, String)>,
    pub default_folders: Vec<DefaultFolder>,
    pub shared_folder: String,

    pub http_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    pub http_use_forwarded: bool,

    pub encrypt: bool,
    pub encrypt_append: bool,

    pub principal_allow_lookups: bool,

    pub capabilities: BaseCapabilities,
    pub session_purge_frequency: SimpleCron,
    pub account_purge_frequency: SimpleCron,
}

#[derive(Clone, Debug)]
pub struct DefaultFolder {
    pub name: String,
    pub aliases: Vec<String>,
    pub special_use: SpecialUse,
    pub subscribe: bool,
    pub create: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SpecialUse {
    Inbox,
    Trash,
    Junk,
    Drafts,
    Archive,
    Sent,
    Shared,
    None,
}

impl JmapConfig {
    pub fn parse(config: &mut Config) -> Self {
        // Parse HTTP headers
        let mut http_headers = config
            .values("server.http.headers")
            .map(|(_, v)| {
                if let Some((k, v)) = v.split_once(':') {
                    Ok((
                        hyper::header::HeaderName::from_str(k.trim()).map_err(|err| {
                            format!(
                                "Invalid header found in property \"server.http.headers\": {}",
                                err
                            )
                        })?,
                        hyper::header::HeaderValue::from_str(v.trim()).map_err(|err| {
                            format!(
                                "Invalid header found in property \"server.http.headers\": {}",
                                err
                            )
                        })?,
                    ))
                } else {
                    Err(format!(
                        "Invalid header found in property \"server.http.headers\": {}",
                        v
                    ))
                }
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| config.new_parse_error("server.http.headers", e))
            .unwrap_or_default();

        // Parse default folders
        let mut default_folders = Vec::new();
        let mut shared_folder = "Shared Folders".to_string();
        for key in config
            .sub_keys("jmap.folders", ".name")
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
        {
            match SpecialUse::parse_value(&key) {
                Ok(SpecialUse::Shared) => {
                    if let Some(value) = config.value(&key) {
                        shared_folder = value.to_string();
                    }
                }
                Ok(special_use) => {
                    let subscribe = config
                        .property_or_default(("jmap.folders", key.as_str(), "subscribe"), "true")
                        .unwrap_or(true);
                    let create = config
                        .property_or_default(("jmap.folders", key.as_str(), "create"), "true")
                        .unwrap_or(true)
                        | [SpecialUse::Inbox, SpecialUse::Trash, SpecialUse::Junk]
                            .contains(&special_use);
                    if let Some(name) = config
                        .value(("jmap.folders", key.as_str(), "name"))
                        .map(|name| name.trim())
                        .filter(|name| !name.is_empty())
                    {
                        default_folders.push(DefaultFolder {
                            name: name.to_string(),
                            aliases: config
                                .value(("jmap.folders", key.as_str(), "aliases"))
                                .unwrap_or_default()
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect(),
                            special_use,
                            subscribe,
                            create,
                        });
                    }
                }
                Err(err) => {
                    config.new_parse_error(key, err);
                }
            }
        }
        for (special_use, name) in [
            (SpecialUse::Inbox, "Inbox"),
            (SpecialUse::Trash, "Deleted Items"),
            (SpecialUse::Junk, "Junk Mail"),
            (SpecialUse::Drafts, "Drafts"),
            (SpecialUse::Sent, "Sent Items"),
        ] {
            if !default_folders.iter().any(|f| f.special_use == special_use) {
                default_folders.push(DefaultFolder {
                    name: name.to_string(),
                    aliases: Vec::new(),
                    special_use,
                    subscribe: true,
                    create: true,
                });
            }
        }

        // Add permissive CORS headers
        if config
            .property::<bool>("server.http.permissive-cors")
            .unwrap_or(false)
        {
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            ));
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
                hyper::header::HeaderValue::from_static(
                    "Authorization, Content-Type, Accept, X-Requested-With",
                ),
            ));
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
                hyper::header::HeaderValue::from_static(
                    "POST, GET, PATCH, PUT, DELETE, HEAD, OPTIONS",
                ),
            ));
        }

        // Add HTTP Strict Transport Security
        if config.property::<bool>("server.http.hsts").unwrap_or(false) {
            http_headers.push((
                hyper::header::STRICT_TRANSPORT_SECURITY,
                hyper::header::HeaderValue::from_static(
                    "max-age=31536000; includeSubDomains; preload",
                ),
            ));
        }

        let mut jmap = JmapConfig {
            default_language: Language::from_iso_639(
                config
                    .value("storage.full-text.default-language")
                    .unwrap_or("en"),
            )
            .unwrap_or(Language::English),
            query_max_results: config
                .property("jmap.protocol.query.max-results")
                .unwrap_or(5000),
            changes_max_results: config
                .property("jmap.protocol.changes.max-results")
                .unwrap_or(5000),
            changes_max_history: config
                .property_or_default::<Option<Duration>>("jmap.protocol.changes.max-history", "30d")
                .unwrap_or_default(),
            snippet_max_results: config
                .property("jmap.protocol.search-snippet.max-results")
                .unwrap_or(100),
            request_max_size: config
                .property("jmap.protocol.request.max-size")
                .unwrap_or(10000000),
            request_max_calls: config
                .property("jmap.protocol.request.max-calls")
                .unwrap_or(16),
            request_max_concurrent: config
                .property("jmap.protocol.request.max-concurrent")
                .unwrap_or(4),
            get_max_objects: config
                .property("jmap.protocol.get.max-objects")
                .unwrap_or(500),
            set_max_objects: config
                .property("jmap.protocol.set.max-objects")
                .unwrap_or(500),
            upload_max_size: config
                .property("jmap.protocol.upload.max-size")
                .unwrap_or(50000000),
            upload_max_concurrent: config
                .property("jmap.protocol.upload.max-concurrent")
                .unwrap_or(4),
            upload_tmp_quota_size: config
                .property("jmap.protocol.upload.quota.size")
                .unwrap_or(50000000),
            upload_tmp_quota_amount: config
                .property("jmap.protocol.upload.quota.files")
                .unwrap_or(1000),
            upload_tmp_ttl: config
                .property_or_default::<Duration>("jmap.protocol.upload.ttl", "1h")
                .unwrap_or_else(|| Duration::from_secs(3600))
                .as_secs(),
            mailbox_max_depth: config.property("jmap.mailbox.max-depth").unwrap_or(10),
            mailbox_name_max_len: config
                .property("jmap.mailbox.max-name-length")
                .unwrap_or(255),
            mail_attachments_max_size: config
                .property("jmap.email.max-attachment-size")
                .unwrap_or(50000000),
            mail_max_size: config.property("jmap.email.max-size").unwrap_or(75000000),
            mail_parse_max_items: config.property("jmap.email.parse.max-items").unwrap_or(10),
            mail_autoexpunge_after: config
                .property_or_default::<Option<Duration>>("jmap.email.auto-expunge", "30d")
                .unwrap_or_default(),
            sieve_max_script_name: config
                .property("sieve.untrusted.limits.name-length")
                .unwrap_or(512),
            sieve_max_scripts: config
                .property("sieve.untrusted.limits.max-scripts")
                .unwrap_or(256),
            capabilities: BaseCapabilities::default(),
            session_cache_ttl: config
                .property("cache.session.ttl")
                .unwrap_or(Duration::from_secs(3600)),
            rate_authenticated: config
                .property_or_default::<Option<Rate>>("jmap.rate-limit.account", "1000/1m")
                .unwrap_or_default(),
            rate_authenticate_req: config
                .property_or_default::<Option<Rate>>("authentication.rate-limit", "10/1m")
                .unwrap_or_default(),
            rate_anonymous: config
                .property_or_default::<Option<Rate>>("jmap.rate-limit.anonymous", "100/1m")
                .unwrap_or_default(),
            oauth_key: config
                .value("oauth.key")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    thread_rng()
                        .sample_iter(Alphanumeric)
                        .take(64)
                        .map(char::from)
                        .collect::<String>()
                }),
            oauth_expiry_user_code: config
                .property_or_default::<Duration>("oauth.expiry.user-code", "30m")
                .unwrap_or_else(|| Duration::from_secs(30 * 60))
                .as_secs(),
            oauth_expiry_auth_code: config
                .property_or_default::<Duration>("oauth.expiry.auth-code", "10m")
                .unwrap_or_else(|| Duration::from_secs(10 * 60))
                .as_secs(),
            oauth_expiry_token: config
                .property_or_default::<Duration>("oauth.expiry.token", "1h")
                .unwrap_or_else(|| Duration::from_secs(60 * 60))
                .as_secs(),
            oauth_expiry_refresh_token: config
                .property_or_default::<Duration>("oauth.expiry.refresh-token", "30d")
                .unwrap_or_else(|| Duration::from_secs(30 * 24 * 60 * 60))
                .as_secs(),
            oauth_expiry_refresh_token_renew: config
                .property_or_default::<Duration>("oauth.expiry.refresh-token-renew", "4d")
                .unwrap_or_else(|| Duration::from_secs(4 * 24 * 60 * 60))
                .as_secs(),
            oauth_max_auth_attempts: config
                .property_or_default("oauth.auth.max-attempts", "3")
                .unwrap_or(10),
            event_source_throttle: config
                .property_or_default("jmap.event-source.throttle", "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            web_socket_throttle: config
                .property_or_default("jmap.web-socket.throttle", "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            web_socket_timeout: config
                .property_or_default("jmap.web-socket.timeout", "10m")
                .unwrap_or_else(|| Duration::from_secs(10 * 60)),
            web_socket_heartbeat: config
                .property_or_default("jmap.web-socket.heartbeat", "1m")
                .unwrap_or_else(|| Duration::from_secs(60)),
            push_max_total: config
                .property_or_default("jmap.push.max-total", "100")
                .unwrap_or(100),
            principal_allow_lookups: config
                .property("jmap.principal.allow-lookups")
                .unwrap_or(true),
            encrypt: config
                .property_or_default("storage.encryption.enable", "true")
                .unwrap_or(true),
            encrypt_append: config
                .property_or_default("storage.encryption.append", "false")
                .unwrap_or(false),
            spam_header: config
                .property_or_default::<Option<String>>("spam.header.is-spam", "X-Spam-Status: Yes")
                .unwrap_or_default()
                .and_then(|v| {
                    v.split_once(':').map(|(k, v)| {
                        (
                            mail_parser::HeaderName::parse(k.trim().to_string()).unwrap(),
                            v.trim().to_string(),
                        )
                    })
                }),
            http_use_forwarded: config
                .property("server.http.use-x-forwarded")
                .unwrap_or(false),
            http_headers,
            push_attempt_interval: config
                .property_or_default("jmap.push.attempts.interval", "1m")
                .unwrap_or_else(|| Duration::from_secs(60)),
            push_attempts_max: config
                .property_or_default("jmap.push.attempts.max", "3")
                .unwrap_or(3),
            push_retry_interval: config
                .property_or_default("jmap.push.retry.interval", "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            push_timeout: config
                .property_or_default("jmap.push.timeout.request", "10s")
                .unwrap_or_else(|| Duration::from_secs(10)),
            push_verify_timeout: config
                .property_or_default("jmap.push.timeout.verify", "1m")
                .unwrap_or_else(|| Duration::from_secs(60)),
            push_throttle: config
                .property_or_default("jmap.push.throttle", "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            session_purge_frequency: config
                .property_or_default::<SimpleCron>("jmap.session.purge.frequency", "15 * *")
                .unwrap_or_else(|| SimpleCron::parse_value("15 * *").unwrap()),
            account_purge_frequency: config
                .property_or_default::<SimpleCron>("jmap.account.purge.frequency", "0 0 *")
                .unwrap_or_else(|| SimpleCron::parse_value("0 0 *").unwrap()),
            fallback_admin: config
                .value("authentication.fallback-admin.user")
                .and_then(|u| {
                    config
                        .value("authentication.fallback-admin.secret")
                        .map(|p| (u.to_string(), p.to_string()))
                }),
            master_user: config.value("authentication.master.user").and_then(|u| {
                config
                    .value("authentication.master.secret")
                    .map(|p| (u.to_string(), p.to_string()))
            }),
            default_folders,
            shared_folder,
        };

        // Add capabilities
        jmap.add_capabilites(config);
        jmap
    }
}

impl ParseValue for SpecialUse {
    fn parse_value(value: &str) -> utils::config::Result<Self> {
        match value {
            "inbox" => Ok(SpecialUse::Inbox),
            "trash" => Ok(SpecialUse::Trash),
            "junk" => Ok(SpecialUse::Junk),
            "drafts" => Ok(SpecialUse::Drafts),
            "archive" => Ok(SpecialUse::Archive),
            "sent" => Ok(SpecialUse::Sent),
            "shared" => Ok(SpecialUse::Shared),
            //"none" => Ok(SpecialUse::None),
            other => Err(format!("Unknown folder role {other:?}")),
        }
    }
}
