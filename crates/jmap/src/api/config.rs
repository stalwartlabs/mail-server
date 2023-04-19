use store::fts::Language;

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
            request_max_size: settings
                .property("jmap.protocol.request.max-size")?
                .unwrap_or(10000000),
            request_max_calls: settings
                .property("jmap.protocol.request.max-calls")?
                .unwrap_or(16),
            request_max_concurrent: settings
                .property("jmap.protocol.request.max-concurrent")?
                .unwrap_or(4),
            request_max_concurrent_total: settings
                .property("jmap.protocol.request.max-concurrent-total")?
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
            sieve_max_script_name: settings
                .property("jmap.sieve.max-name-length")?
                .unwrap_or(512),
            sieve_max_scripts: settings
                .property("jmap.protocol.max-scripts")?
                .unwrap_or(256),
            capabilities: BaseCapabilities::default(),
        };
        config.add_capabilites(settings);
        Ok(config)
    }
}
