/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::Config;

#[derive(Debug, Clone, Default)]
pub struct DavConfig {
    pub max_request_size: usize,
    pub dead_property_size: Option<usize>,
    pub live_property_size: usize,
    pub max_lock_timeout: u64,
    pub max_locks_per_user: usize,
    pub max_changes: usize,
    pub max_match_results: usize,
    pub max_vcard_size: usize,
    pub max_ical_size: usize,
    pub max_ical_instances: usize,
    pub max_ical_attendees_per_instance: usize,
    pub default_calendar_name: Option<String>,
    pub default_addressbook_name: Option<String>,
    pub default_calendar_display_name: Option<String>,
    pub default_addressbook_display_name: Option<String>,
}

impl DavConfig {
    pub fn parse(config: &mut Config) -> Self {
        DavConfig {
            max_request_size: config
                .property("dav.limits.size.request")
                .unwrap_or(25 * 1024 * 1024),
            dead_property_size: config
                .property_or_default::<Option<usize>>("dav.limits.size.dead-property", "1024")
                .unwrap_or(Some(1024)),
            live_property_size: config
                .property("dav.limits.size.live-property")
                .unwrap_or(250),
            max_lock_timeout: config.property("dav.limits.timeout.max-lock").unwrap_or(60),
            max_locks_per_user: config
                .property("dav.limits.max-locks-per-user")
                .unwrap_or(10),
            max_changes: config.property("dav.limits.max-changes").unwrap_or(1000),
            max_match_results: config
                .property("dav.limits.max-match-results")
                .unwrap_or(1000),
            max_vcard_size: config
                .property("dav.limits.size.vcard")
                .unwrap_or(512 * 1024),
            max_ical_size: config
                .property("dav.limits.size.ical")
                .unwrap_or(512 * 1024),
            default_calendar_name: config
                .property_or_default::<Option<String>>("dav.default.calendar.name", "default")
                .unwrap_or_default(),
            default_addressbook_name: config
                .property_or_default::<Option<String>>("dav.default.addressbook.name", "default")
                .unwrap_or_default(),
            default_calendar_display_name: config
                .property_or_default::<Option<String>>(
                    "dav.default.calendar.display-name",
                    "Default Calendar",
                )
                .unwrap_or_default(),
            default_addressbook_display_name: config
                .property_or_default::<Option<String>>(
                    "dav.default.addressbook.display-name",
                    "Default Address Book",
                )
                .unwrap_or_default(),
            max_ical_instances: config
                .property("dav.limits.ical.max-instances")
                .unwrap_or(1000),
            max_ical_attendees_per_instance: config
                .property("dav.limits.ical.max-attendees-per-instance")
                .unwrap_or(1000),
        }
    }
}
