/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponentType, ICalendarDuration, ICalendarEntry, ICalendarMethod,
        ICalendarParameter, ICalendarParticipationRole, ICalendarParticipationStatus,
        ICalendarPeriod, ICalendarProperty, ICalendarRecurrenceRule,
        ICalendarScheduleForceSendValue, ICalendarStatus, ICalendarUserTypes, ICalendarValue, Uri,
    },
};
use ahash::{AHashMap, AHashSet};
use std::{fmt::Display, hash::Hash};

pub mod attendee;
pub mod event_cancel;
pub mod event_create;
pub mod event_update;
pub mod inbound;
pub mod itip;
pub mod organizer;
pub mod snapshot;

#[derive(Debug)]
pub struct ItipSnapshots<'x> {
    pub organizer: Organizer<'x>,
    pub uid: &'x str,
    pub components: AHashMap<InstanceId, ItipSnapshot<'x>>,
}

#[derive(Debug, Default)]
pub struct ItipSnapshot<'x> {
    pub comp_id: u16,
    pub attendees: AHashSet<Attendee<'x>>,
    pub dtstamp: Option<&'x PartialDateTime>,
    pub entries: AHashSet<ItipEntry<'x>>,
    pub sequence: Option<i64>,
    pub request_status: Vec<&'x str>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ItipEntry<'x> {
    pub name: &'x ICalendarProperty,
    pub value: ItipEntryValue<'x>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ItipEntryValue<'x> {
    DateTime(ItipDateTime<'x>),
    Period(&'x ICalendarPeriod),
    Duration(&'x ICalendarDuration),
    Status(&'x ICalendarStatus),
    RRule(&'x ICalendarRecurrenceRule),
    Text(&'x str),
    Integer(i64),
}

#[derive(Debug)]
pub struct ItipDateTime<'x> {
    pub date: &'x PartialDateTime,
    pub tz_id: Option<&'x str>,
    pub timestamp: i64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum InstanceId {
    Main,
    Recurrence(RecurrenceId),
}

#[derive(Debug)]
pub struct RecurrenceId {
    pub entry_id: u16,
    pub date: i64,
    pub this_and_future: bool,
}

#[derive(Debug)]
pub struct Attendee<'x> {
    pub entry_id: u16,
    pub email: Email,
    pub part_stat: Option<&'x ICalendarParticipationStatus>,
    pub delegated_from: Vec<Email>,
    pub delegated_to: Vec<Email>,
    pub role: Option<&'x ICalendarParticipationRole>,
    pub cu_type: Option<&'x ICalendarUserTypes>,
    pub sent_by: Option<Email>,
    pub rsvp: Option<bool>,
    pub is_server_scheduling: bool,
    pub force_send: Option<&'x ICalendarScheduleForceSendValue>,
}

#[derive(Debug)]
pub struct Organizer<'x> {
    pub entry_id: u16,
    pub email: Email,
    pub is_server_scheduling: bool,
    pub force_send: Option<&'x ICalendarScheduleForceSendValue>,
}

#[derive(Debug)]
pub struct Email {
    pub email: String,
    pub is_local: bool,
}

#[derive(Debug)]
pub enum ItipError {
    NoSchedulingInfo,
    OtherSchedulingAgent,
    NotOrganizer,
    NotOrganizerNorAttendee,
    NothingToSend,
    MissingUid,
    MultipleUid,
    MultipleOrganizer,
    MultipleObjectTypes,
    MultipleObjectInstances,
    ChangeNotAllowed,
    OrganizerMismatch,
    MissingMethod,
    InvalidComponentType,
    OutOfSequence,
    SenderIsOrganizer,
    SenderIsNotParticipant(String),
    UnknownParticipant(String),
    UnsupportedMethod(ICalendarMethod),
}

pub struct ItipMessage {
    pub method: ICalendarMethod,
    pub from: String,
    pub to: Vec<String>,
    pub changed_properties: Vec<ICalendarProperty>,
    pub message: ICalendar,
}

impl ICalendarComponentType {
    pub fn is_scheduling_object(&self) -> bool {
        matches!(
            self,
            ICalendarComponentType::VEvent
                | ICalendarComponentType::VTodo
                | ICalendarComponentType::VJournal
                | ICalendarComponentType::VFreebusy
        )
    }
}

impl ItipSnapshot<'_> {
    pub fn has_local_attendee(&self) -> bool {
        self.attendees
            .iter()
            .any(|attendee| attendee.email.is_local)
    }

    pub fn local_attendee(&self) -> Option<&Attendee<'_>> {
        self.attendees
            .iter()
            .find(|attendee| attendee.email.is_local)
    }

    pub fn attendee_delegates<'x>(
        &'x self,
        attendee: &'x Attendee<'x>,
    ) -> impl Iterator<Item = &'x Attendee<'x>> + 'x {
        self.attendees.iter().filter(|item| {
            !item.email.is_local
                && attendee
                    .delegated_from
                    .iter()
                    .any(|d| d.email == attendee.email.email)
        })
    }
}

impl Attendee<'_> {
    pub fn send_invite_messages(&self) -> bool {
        !self.email.is_local
            && self.is_server_scheduling
            && self.rsvp.is_none_or(|rsvp| rsvp)
            && (self.force_send.is_some()
                || self.part_stat.is_none_or(|part_stat| {
                    part_stat == &ICalendarParticipationStatus::NeedsAction
                }))
    }

    pub fn send_update_messages(&self) -> bool {
        !self.email.is_local
            && self.is_server_scheduling
            && self.rsvp.is_none_or(|rsvp| rsvp)
            && (self.force_send.is_some()
                || self
                    .part_stat
                    .is_none_or(|part_stat| part_stat != &ICalendarParticipationStatus::Declined))
    }
}

impl Email {
    pub fn new(email: &str, local_addresses: &[&str]) -> Option<Self> {
        email.contains('@').then(|| {
            let email = email.trim().trim_start_matches("mailto:").to_lowercase();
            let is_local = local_addresses.contains(&email.as_str());
            Email { email, is_local }
        })
    }

    pub fn from_uri(uri: &Uri, local_addresses: &[&str]) -> Option<Self> {
        if let Uri::Location(uri) = uri {
            Email::new(uri.as_str(), local_addresses)
        } else {
            None
        }
    }
}

impl PartialEq for Attendee<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
            && self.part_stat == other.part_stat
            && self.delegated_from == other.delegated_from
            && self.delegated_to == other.delegated_to
            && self.role == other.role
            && self.cu_type == other.cu_type
            && self.sent_by == other.sent_by
    }
}

impl Eq for Attendee<'_> {}

impl Hash for Attendee<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
        self.part_stat.hash(state);
        self.delegated_from.hash(state);
        self.delegated_to.hash(state);
        self.role.hash(state);
        self.cu_type.hash(state);
        self.sent_by.hash(state);
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mailto:{}", self.email)
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
    }
}

impl Eq for Email {}

impl PartialEq for RecurrenceId {
    fn eq(&self, other: &Self) -> bool {
        self.date == other.date && self.this_and_future == other.this_and_future
    }
}

impl Eq for RecurrenceId {}

impl Hash for RecurrenceId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.date.hash(state);
        self.this_and_future.hash(state);
    }
}

impl PartialEq for ItipDateTime<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp
    }
}
impl Eq for ItipDateTime<'_> {}

impl Hash for ItipDateTime<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.timestamp.hash(state);
    }
}

impl ItipDateTime<'_> {
    pub fn to_entry(&self, name: ICalendarProperty) -> ICalendarEntry {
        ICalendarEntry {
            name,
            params: self
                .tz_id
                .map(|tz_id| vec![ICalendarParameter::Tzid(tz_id.to_string())])
                .unwrap_or_default(),
            values: vec![ICalendarValue::PartialDateTime(Box::new(self.date.clone()))],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        common::PartialDateTime,
        icalendar::{ICalendar, ICalendarProperty, ICalendarValue},
        scheduling::{
            event_cancel::itip_cancel,
            event_create::itip_create,
            event_update::itip_update,
            inbound::{itip_merge_changes, itip_process_message, MergeResult},
            itip::itip_import_message,
            snapshot::itip_snapshot,
            ItipMessage,
        },
    };
    use ahash::AHashMap;
    use std::collections::hash_map::Entry;

    struct Test {
        test_name: String,
        command: Command,
        line_num: usize,
        parameters: Vec<String>,
        payload: String,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Command {
        Put,
        Get,
        Delete,
        Expect,
        Send,
    }

    #[test]
    fn scheduling_tests() {
        for entry in std::fs::read_dir("resources/scheduling").unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "txt") {
                continue;
            }
            let file_name = path.file_name().unwrap().to_str().unwrap();
            let rules = std::fs::read_to_string(&path).unwrap();
            let mut last_comment = "";
            let mut last_command = "";
            let mut last_line_num = 0;
            let mut payload = String::new();
            let mut commands = Vec::new();

            for (line_num, line) in rules.lines().enumerate() {
                if line.starts_with('#') {
                    last_comment = line.trim_start_matches('#').trim();
                } else if let Some(command) = line.strip_prefix("> ") {
                    last_command = command.trim();
                    last_line_num = line_num;
                } else if !line.is_empty() {
                    payload.push_str(line);
                    payload.push('\n');
                } else {
                    if last_command.is_empty() && payload.is_empty() {
                        continue;
                    }
                    let mut command_and_args = last_command.split_whitespace();
                    let command = match command_and_args
                        .next()
                        .expect("Command should not be empty")
                    {
                        "put" => Command::Put,
                        "get" => Command::Get,
                        "expect" => Command::Expect,
                        "send" => Command::Send,
                        "delete" => Command::Delete,
                        _ => panic!("Unknown command: {}", last_command),
                    };

                    commands.push(Test {
                        command,
                        test_name: last_comment.to_string(),
                        line_num: last_line_num,
                        parameters: command_and_args.map(String::from).collect(),
                        payload: payload.trim().to_string(),
                    });

                    last_command = "";
                    last_line_num = 0;
                    payload.clear();
                }
            }

            if commands.is_empty() {
                panic!("No commands found in file: {}", file_name);
            } else if !last_command.is_empty() {
                panic!(
                    "File ended with command '{}' at line {} without payload",
                    last_command, last_line_num
                );
            }

            println!("====== Running test: {} ======", file_name);

            let mut store: AHashMap<String, AHashMap<String, ICalendar>> = AHashMap::new();
            let mut dtstamp_map: AHashMap<PartialDateTime, usize> = AHashMap::new();
            let mut last_itip = None;

            for command in &commands {
                if command.command != Command::Put {
                    println!("{} (line {})", command.test_name, command.line_num);
                }
                match command.command {
                    Command::Put => {
                        let account = command
                            .parameters
                            .first()
                            .expect("Account parameter is required");
                        let name = command
                            .parameters
                            .get(1)
                            .expect("Name parameter is required");
                        let mut ical = ICalendar::parse(&command.payload)
                            .expect("Failed to parse iCalendar payload");
                        match store
                            .entry(account.to_string())
                            .or_default()
                            .entry(name.to_string())
                        {
                            Entry::Occupied(mut entry) => {
                                last_itip =
                                    Some(itip_update(&mut ical, entry.get_mut(), &[account]));
                                entry.insert(ical);
                            }
                            Entry::Vacant(entry) => {
                                last_itip = Some(itip_create(&mut ical, &[account]));
                                entry.insert(ical);
                            }
                        }
                    }
                    Command::Get => {
                        let account = command
                            .parameters
                            .first()
                            .expect("Account parameter is required")
                            .as_str();
                        let name = command
                            .parameters
                            .get(1)
                            .expect("Name parameter is required")
                            .as_str();
                        let ical = ICalendar::parse(&command.payload)
                            .expect("Failed to parse iCalendar payload")
                            .to_string()
                            .replace("\r\n", "\n");
                        store
                            .get(account)
                            .and_then(|account_store| account_store.get(name))
                            .map(|stored_ical| {
                                let stored_ical =
                                    normalize_ical(stored_ical.clone(), &mut dtstamp_map);
                                if stored_ical != ical {
                                    panic!(
                                        "ICalendar mismatch for {}: expected {}, got {}",
                                        command.test_name, stored_ical, ical
                                    );
                                }
                            })
                            .unwrap_or_else(|| {
                                panic!(
                                    "ICalendar not found for account: {}, name: {}",
                                    account, name
                                );
                            });
                    }
                    Command::Delete => {
                        let account = command
                            .parameters
                            .first()
                            .expect("Account parameter is required")
                            .as_str();
                        let name = command
                            .parameters
                            .get(1)
                            .expect("Name parameter is required")
                            .as_str();
                        let store = store.get_mut(account).expect("Account not found in store");

                        if let Some(mut ical) = store.remove(name) {
                            last_itip = Some(itip_cancel(&mut ical, &[account]));
                        } else {
                            panic!(
                                "ICalendar not found for account: {}, name: {}",
                                account, name
                            );
                        }
                    }
                    Command::Expect => {
                        let last_itip_str = match last_itip
                            .as_ref()
                            .expect("No last iTIP message to compare against")
                        {
                            Ok(m) => m.to_string(&mut dtstamp_map),
                            Err(e) => format!("{e:?}"),
                        };
                        assert_eq!(
                            command.payload.trim(),
                            last_itip_str.trim(),
                            "iTIP message mismatch for {} at line {}: expected {}, got {}",
                            command.test_name,
                            command.line_num,
                            command.payload,
                            last_itip_str
                        );
                    }
                    Command::Send => {
                        let mut results = String::new();
                        match last_itip {
                            Some(Ok(message)) => {
                                for rcpt in &message.to {
                                    let result = match itip_snapshot(
                                        &message.message,
                                        &[rcpt.as_str()],
                                        false,
                                    ) {
                                        Ok(itip_snapshots) => {
                                            match store
                                                .entry(rcpt.to_string())
                                                .or_default()
                                                .entry(itip_snapshots.uid.to_string())
                                            {
                                                Entry::Occupied(mut entry) => {
                                                    let ical = entry.get_mut();
                                                    let snapshots = itip_snapshot(
                                                        ical,
                                                        &[rcpt.as_str()],
                                                        false,
                                                    )
                                                    .expect("Failed to create iTIP snapshot");

                                                    match itip_process_message(
                                                        ical,
                                                        snapshots,
                                                        &message.message,
                                                        itip_snapshots,
                                                        message.from.clone(),
                                                    ) {
                                                        Ok(result) => match result {
                                                            MergeResult::Actions(changes) => {
                                                                itip_merge_changes(ical, changes);
                                                                Ok(None)
                                                            }
                                                            MergeResult::Message(message) => {
                                                                Ok(Some(message))
                                                            }
                                                            MergeResult::None => Ok(None),
                                                        },
                                                        Err(err) => Err(err),
                                                    }
                                                }
                                                Entry::Vacant(entry) => {
                                                    let mut message = message.message.clone();
                                                    itip_import_message(&mut message)
                                                        .expect("Failed to import iTIP message");
                                                    entry.insert(message);
                                                    Ok(None)
                                                }
                                            }
                                        }
                                        Err(err) => Err(err),
                                    };

                                    match result {
                                        Ok(Some(itip_message)) => {
                                            results.push_str(
                                                &itip_message.to_string(&mut dtstamp_map),
                                            );
                                        }
                                        Ok(None) => {}
                                        Err(e) => {
                                            results.push_str(&format!("{e:?}"));
                                        }
                                    }
                                }

                                assert_eq!(
                                    results.trim(), command.payload.trim(),
                                    "iTIP send result mismatch for {} at line {}: expected {}, got {}",
                                    command.test_name, command.line_num, command.payload, results
                                );
                            }
                            Some(Err(e)) => {
                                panic!(
                                    "Failed to create iTIP message for {} at line {}: {:?}",
                                    command.test_name, command.line_num, e
                                );
                            }
                            None => {
                                panic!(
                                    "No iTIP message to send for {} at line {}",
                                    command.test_name, command.line_num
                                );
                            }
                        }
                        last_itip = None;
                    }
                }
            }
        }
    }

    impl ItipMessage {
        pub fn to_string(&self, map: &mut AHashMap<PartialDateTime, usize>) -> String {
            use std::fmt::Write;
            let mut f = String::new();
            let mut to = self.to.iter().map(|t| t.as_str()).collect::<Vec<_>>();
            to.sort_unstable();
            let mut changed = self
                .changed_properties
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>();
            changed.sort_unstable();
            writeln!(&mut f, "from: {}", self.from).unwrap();
            writeln!(&mut f, "to: {}", to.join(", ")).unwrap();
            writeln!(&mut f, "changes: {}", changed.join(", ")).unwrap();
            write!(&mut f, "{}", normalize_ical(self.message.clone(), map)).unwrap();
            f
        }
    }

    fn normalize_ical(mut ical: ICalendar, map: &mut AHashMap<PartialDateTime, usize>) -> String {
        let mut comps = ical
            .components
            .iter()
            .enumerate()
            .filter(|(comp_id, _)| {
                ical.components[0]
                    .component_ids
                    .contains(&(*comp_id as u16))
            })
            .collect::<Vec<_>>();
        comps.sort_unstable_by_key(|(_, comp)| *comp);
        ical.components[0].component_ids =
            comps.iter().map(|(comp_id, _)| *comp_id as u16).collect();

        for comp in &mut ical.components {
            for entry in &mut comp.entries {
                if let (ICalendarProperty::Dtstamp, Some(ICalendarValue::PartialDateTime(dt))) =
                    (&entry.name, entry.values.first())
                {
                    if let Some(index) = map.get(dt) {
                        entry.values = vec![ICalendarValue::Integer(*index as i64)];
                    } else {
                        let index = map.len();
                        map.insert(dt.as_ref().clone(), index);
                        entry.values = vec![ICalendarValue::Integer(index as i64)];
                    }
                }
            }
        }
        ical.to_string().replace("\r\n", "\n")
    }
}
