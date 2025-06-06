/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{str::FromStr, time::Duration};

use utils::{config::Config, template::Template};

#[derive(Debug, Clone, Default)]
pub struct GroupwareConfig {
    // DAV settings
    pub max_request_size: usize,
    pub dead_property_size: Option<usize>,
    pub live_property_size: usize,
    pub max_lock_timeout: u64,
    pub max_locks_per_user: usize,
    pub max_results: usize,

    // Calendar settings
    pub max_ical_size: usize,
    pub max_ical_instances: usize,
    pub max_ical_attendees_per_instance: usize,
    pub default_calendar_name: Option<String>,
    pub default_calendar_display_name: Option<String>,
    pub alarms_enabled: bool,
    pub alarms_minimum_interval: i64,
    pub alarms_allow_external_recipients: bool,
    pub alarms_from_name: String,
    pub alarms_from_email: Option<String>,
    pub alarms_template: Template<CalendarTemplateVariable>,

    // Addressbook settings
    pub max_vcard_size: usize,
    pub default_addressbook_name: Option<String>,
    pub default_addressbook_display_name: Option<String>,

    // File storage settings
    pub max_file_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub enum CalendarTemplateVariable {
    #[default]
    PageTitle,
    Header,
    Footer,
    EventTitle,
    EventDescription,
    EventDetails,
    ActionUrl,
    ActionName,
    AttendeesTitle,
    Attendees,
    Key,
    Value,
    LogoCid,
}

impl GroupwareConfig {
    pub fn parse(config: &mut Config) -> Self {
        GroupwareConfig {
            max_request_size: config
                .property("dav.request.max-size")
                .unwrap_or(25 * 1024 * 1024),
            dead_property_size: config
                .property_or_default::<Option<usize>>("dav.property.max-size.dead", "1024")
                .unwrap_or(Some(1024)),
            live_property_size: config.property("dav.property.max-size.live").unwrap_or(250),
            max_lock_timeout: config
                .property::<Duration>("dav.lock.max-timeout")
                .map(|d| d.as_secs())
                .unwrap_or(3600),
            max_locks_per_user: config.property("dav.locks.max-per-user").unwrap_or(10),
            max_results: config.property("dav.response.max-results").unwrap_or(2000),
            default_calendar_name: config
                .property_or_default::<Option<String>>("calendar.default.href-name", "default")
                .unwrap_or_default(),
            default_calendar_display_name: config
                .property_or_default::<Option<String>>(
                    "calendar.default.display-name",
                    "Stalwart Calendar",
                )
                .unwrap_or_default(),
            default_addressbook_name: config
                .property_or_default::<Option<String>>("contacts.default.href-name", "default")
                .unwrap_or_default(),
            default_addressbook_display_name: config
                .property_or_default::<Option<String>>(
                    "contacts.default.display-name",
                    "Stalwart Address Book",
                )
                .unwrap_or_default(),
            max_ical_size: config.property("calendar.max-size").unwrap_or(512 * 1024),
            max_ical_instances: config
                .property("calendar.max-recurrence-expansions")
                .unwrap_or(3000),
            max_ical_attendees_per_instance: config
                .property("calendar.max-attendees-per-instance")
                .unwrap_or(20),
            max_vcard_size: config.property("contacts.max-size").unwrap_or(512 * 1024),
            max_file_size: config
                .property("file-storage.max-size")
                .unwrap_or(25 * 1024 * 1024),
            alarms_enabled: config.property("calendar.alarms.enabled").unwrap_or(true),
            alarms_minimum_interval: config
                .property_or_default::<Duration>("calendar.alarms.minimum-interval", "1h")
                .unwrap_or(Duration::from_secs(60 * 60))
                .as_secs() as i64,
            alarms_allow_external_recipients: config
                .property("calendar.alarms.allow-external-recipients")
                .unwrap_or(false),
            alarms_from_name: config
                .value("calendar.alarms.from.name")
                .unwrap_or("Stalwart Calendar")
                .to_string(),
            alarms_from_email: config
                .value("calendar.alarms.from.email")
                .map(|s| s.to_string()),
            alarms_template: Template::parse(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../resources/email-templates/calendar-alarm.html"
            )))
            .expect("Failed to parse calendar template"),
        }
    }
}

impl FromStr for CalendarTemplateVariable {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "page_title" => Ok(CalendarTemplateVariable::PageTitle),
            "header" => Ok(CalendarTemplateVariable::Header),
            "footer" => Ok(CalendarTemplateVariable::Footer),
            "event_title" => Ok(CalendarTemplateVariable::EventTitle),
            "event_description" => Ok(CalendarTemplateVariable::EventDescription),
            "event_details" => Ok(CalendarTemplateVariable::EventDetails),
            "action_url" => Ok(CalendarTemplateVariable::ActionUrl),
            "action_name" => Ok(CalendarTemplateVariable::ActionName),
            "attendees" => Ok(CalendarTemplateVariable::Attendees),
            "attendees_title" => Ok(CalendarTemplateVariable::AttendeesTitle),
            "key" => Ok(CalendarTemplateVariable::Key),
            "value" => Ok(CalendarTemplateVariable::Value),
            "logo_cid" => Ok(CalendarTemplateVariable::LogoCid),
            _ => Err(format!("Unknown calendar template variable: {}", s)),
        }
    }
}
