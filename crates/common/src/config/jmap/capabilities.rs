/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use jmap_proto::{
    request::capability::{
        BlobCapabilities, Capabilities, Capability, CoreCapabilities, EmptyCapabilities,
        MailCapabilities, SieveAccountCapabilities, SieveSessionCapabilities,
        SubmissionCapabilities,
    },
    types::type_state::DataType,
};
use utils::{config::Config, map::vec_map::VecMap};

use super::settings::JmapConfig;

impl JmapConfig {
    pub fn add_capabilites(&mut self, config: &mut Config) {
        // Add core capabilities
        self.capabilities.session.append(
            Capability::Core,
            Capabilities::Core(CoreCapabilities {
                max_size_upload: self.upload_max_size,
                max_concurrent_upload: self.upload_max_concurrent as usize,
                max_size_request: self.request_max_size,
                max_concurrent_requests: self.request_max_concurrent as usize,
                max_calls_in_request: self.request_max_calls,
                max_objects_in_get: self.get_max_objects,
                max_objects_in_set: self.set_max_objects,
                collation_algorithms: vec![
                    "i;ascii-numeric".to_string(),
                    "i;ascii-casemap".to_string(),
                    "i;unicode-casemap".to_string(),
                ],
            }),
        );

        // Add email capabilities
        self.capabilities.session.append(
            Capability::Mail,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.append(
            Capability::Mail,
            Capabilities::Mail(MailCapabilities {
                max_mailboxes_per_email: None,
                max_mailbox_depth: self.mailbox_max_depth,
                max_size_mailbox_name: self.mailbox_name_max_len,
                max_size_attachments_per_email: self.mail_attachments_max_size,
                email_query_sort_options: [
                    "receivedAt",
                    "size",
                    "from",
                    "to",
                    "subject",
                    "sentAt",
                    "hasKeyword",
                    "allInThreadHaveKeyword",
                    "someInThreadHaveKeyword",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                may_create_top_level_mailbox: true,
            }),
        );

        // Add submission capabilities
        self.capabilities.session.append(
            Capability::Submission,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.append(
            Capability::Submission,
            Capabilities::Submission(SubmissionCapabilities {
                max_delayed_send: 86400 * 30,
                submission_extensions: VecMap::from_iter([
                    ("FUTURERELEASE".to_string(), Vec::new()),
                    ("SIZE".to_string(), Vec::new()),
                    ("DSN".to_string(), Vec::new()),
                    ("DELIVERYBY".to_string(), Vec::new()),
                    ("MT-PRIORITY".to_string(), vec!["MIXER".to_string()]),
                    ("REQUIRETLS".to_string(), vec![]),
                ]),
            }),
        );

        // Add vacation response capabilities
        self.capabilities.session.append(
            Capability::VacationResponse,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.append(
            Capability::VacationResponse,
            Capabilities::Empty(EmptyCapabilities::default()),
        );

        // Add Sieve capabilities
        let mut notification_methods = Vec::new();

        for (_, uri) in config.values("sieve.untrusted.notification-uris") {
            notification_methods.push(uri.to_string());
        }
        if notification_methods.is_empty() {
            notification_methods.push("mailto".to_string());
        }

        let mut capabilities: AHashSet<sieve::compiler::grammar::Capability> =
            AHashSet::from_iter(sieve::compiler::grammar::Capability::all().iter().cloned());

        for (_, capability) in config.values("sieve.untrusted.disabled-capabilities") {
            capabilities.remove(&sieve::compiler::grammar::Capability::parse(capability));
        }

        let mut extensions = capabilities
            .into_iter()
            .map(|c| c.to_string())
            .collect::<Vec<String>>();
        extensions.sort_unstable();

        self.capabilities.session.append(
            Capability::Sieve,
            Capabilities::SieveSession(SieveSessionCapabilities::default()),
        );
        self.capabilities.account.append(
            Capability::Sieve,
            Capabilities::SieveAccount(SieveAccountCapabilities {
                max_script_name: self.sieve_max_script_name,
                max_script_size: config
                    .property("sieve.untrusted.max-script-size")
                    .unwrap_or(1024 * 1024),
                max_scripts: self.sieve_max_scripts,
                max_redirects: config
                    .property("sieve.untrusted.max-redirects")
                    .unwrap_or(1),
                extensions,
                notification_methods: if !notification_methods.is_empty() {
                    notification_methods.into()
                } else {
                    None
                },
                ext_lists: None,
            }),
        );

        // Add Blob capabilities
        self.capabilities.session.append(
            Capability::Blob,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.append(
            Capability::Blob,
            Capabilities::Blob(BlobCapabilities {
                max_size_blob_set: (self.request_max_size * 3 / 4) - 512,
                max_data_sources: self.request_max_calls,
                supported_type_names: vec![
                    DataType::Email,
                    DataType::Thread,
                    DataType::SieveScript,
                ],
                supported_digest_algorithms: vec!["sha", "sha-256", "sha-512"],
            }),
        );

        // Add Quota capabilities
        self.capabilities.session.append(
            Capability::Quota,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.append(
            Capability::Quota,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
    }
}
