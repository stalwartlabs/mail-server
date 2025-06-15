/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;

use crate::{
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
        ICalendarParameter, ICalendarParameterName, ICalendarProperty, ICalendarStatus,
        ICalendarValue, Uri,
    },
    scheduling::{
        organizer::organizer_request_full, InstanceId, ItipError, ItipMessage, ItipSnapshots,
    },
};

#[derive(Debug)]
pub enum MergeAction {
    AddEntries {
        component_id: u16,
        entries: Vec<ICalendarEntry>,
    },
    RemoveEntries {
        component_id: u16,
        entries: AHashSet<ICalendarProperty>,
    },
    AddParameters {
        component_id: u16,
        entry_id: u16,
        parameters: Vec<ICalendarParameter>,
    },
    RemoveParameters {
        component_id: u16,
        entry_id: u16,
        parameters: Vec<ICalendarParameterName>,
    },
    AddComponent {
        component: ICalendarComponent,
    },
    RemoveComponent {
        component_id: u16,
    },
}

pub enum MergeResult {
    Actions(Vec<MergeAction>),
    Message(ItipMessage),
    None,
}

pub fn itip_process_message(
    ical: &ICalendar,
    snapshots: ItipSnapshots<'_>,
    itip: &ICalendar,
    itip_snapshots: ItipSnapshots<'_>,
    sender: String,
) -> Result<MergeResult, ItipError> {
    if snapshots.organizer.email != itip_snapshots.organizer.email {
        return Err(ItipError::OrganizerMismatch);
    }

    let method = itip_method(itip)?;
    let mut merge_actions = Vec::new();

    if snapshots.organizer.email.is_local {
        // Handle attendee updates
        if snapshots.organizer.email.email == sender {
            return Err(ItipError::SenderIsOrganizer);
        }
        match method {
            ICalendarMethod::Reply => {
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    if let Some(snapshot) = snapshots.components.get(instance_id) {
                        if let (Some(attendee), Some(updated_attendee)) = (
                            snapshot.attendee_by_email(&sender),
                            itip_snapshot.attendee_by_email(&sender),
                        ) {
                            let itip_component = &itip.components[itip_snapshot.comp_id as usize];
                            let changed_part_stat =
                                attendee.part_stat != updated_attendee.part_stat;
                            let changed_rsvp = attendee.rsvp != updated_attendee.rsvp;
                            let changed_delegated_to =
                                attendee.delegated_to != updated_attendee.delegated_to;
                            let has_request_status = !itip_snapshot.request_status.is_empty();

                            if changed_part_stat
                                || changed_rsvp
                                || changed_delegated_to
                                || has_request_status
                            {
                                // Update participant status
                                let mut add_parameters = Vec::new();
                                let mut remove_parameters = Vec::new();
                                if changed_part_stat {
                                    remove_parameters.push(ICalendarParameterName::Partstat);
                                    if let Some(part_stat) = updated_attendee.part_stat {
                                        add_parameters
                                            .push(ICalendarParameter::Partstat(part_stat.clone()));
                                    }
                                }

                                if changed_rsvp {
                                    remove_parameters.push(ICalendarParameterName::Rsvp);
                                    if let Some(rsvp) = updated_attendee.rsvp {
                                        add_parameters.push(ICalendarParameter::Rsvp(rsvp));
                                    }
                                }

                                if changed_delegated_to {
                                    remove_parameters.push(ICalendarParameterName::DelegatedTo);
                                    if !updated_attendee.delegated_to.is_empty() {
                                        add_parameters.push(ICalendarParameter::DelegatedTo(
                                            updated_attendee
                                                .delegated_to
                                                .iter()
                                                .map(|email| Uri::Location(email.to_string()))
                                                .collect::<Vec<_>>(),
                                        ));
                                    }
                                }

                                if has_request_status {
                                    remove_parameters.push(ICalendarParameterName::ScheduleStatus);
                                    add_parameters.push(ICalendarParameter::ScheduleStatus(
                                        itip_snapshot.request_status.join(","),
                                    ));
                                }

                                merge_actions.push(MergeAction::RemoveParameters {
                                    component_id: snapshot.comp_id,
                                    entry_id: attendee.entry_id,
                                    parameters: remove_parameters,
                                });
                                merge_actions.push(MergeAction::AddParameters {
                                    component_id: snapshot.comp_id,
                                    entry_id: attendee.entry_id,
                                    parameters: add_parameters,
                                });

                                // Add unknown delegated attendees
                                for delegated_to in &updated_attendee.delegated_to {
                                    if snapshot.attendee_by_email(&delegated_to.email).is_none() {
                                        if let Some(delegated_attendee) =
                                            itip_snapshot.attendee_by_email(&delegated_to.email)
                                        {
                                            merge_actions.push(MergeAction::AddEntries {
                                                component_id: snapshot.comp_id,
                                                entries: vec![itip_component.entries
                                                    [delegated_attendee.entry_id as usize]
                                                    .clone()],
                                            });
                                        }
                                    }
                                }
                            }

                            // Add changed properties for VTODO
                            if ical.components[snapshot.comp_id as usize].component_type
                                == ICalendarComponentType::VTodo
                            {
                                let changed_entries = itip_snapshot
                                    .entries
                                    .symmetric_difference(&snapshot.entries)
                                    .filter(|entry| {
                                        matches!(
                                            entry.name,
                                            ICalendarProperty::PercentComplete
                                                | ICalendarProperty::Status
                                                | ICalendarProperty::Completed
                                        )
                                    })
                                    .map(|entry| entry.name.clone())
                                    .collect::<AHashSet<_>>();

                                if !changed_entries.is_empty() {
                                    merge_actions.push(MergeAction::AddEntries {
                                        component_id: snapshot.comp_id,
                                        entries: itip_component
                                            .entries
                                            .iter()
                                            .filter(|entry| changed_entries.contains(&entry.name))
                                            .cloned()
                                            .collect(),
                                    });
                                    merge_actions.push(MergeAction::RemoveEntries {
                                        component_id: snapshot.comp_id,
                                        entries: changed_entries,
                                    });
                                }
                            }
                        } else {
                            return Err(ItipError::SenderIsNotParticipant(sender.clone()));
                        }
                    } else if itip_snapshot.attendee_by_email(&sender).is_some() {
                        // Add component
                        let itip_component = &itip.components[itip_snapshot.comp_id as usize];
                        let is_todo =
                            itip_component.component_type == ICalendarComponentType::VTodo;
                        merge_actions.push(MergeAction::AddComponent {
                            component: ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        matches!(
                                            entry.name,
                                            ICalendarProperty::Organizer
                                                | ICalendarProperty::Attendee
                                                | ICalendarProperty::Uid
                                                | ICalendarProperty::Dtstamp
                                                | ICalendarProperty::Sequence
                                                | ICalendarProperty::RecurrenceId
                                        ) || (is_todo
                                            && matches!(
                                                entry.name,
                                                ICalendarProperty::PercentComplete
                                                    | ICalendarProperty::Status
                                                    | ICalendarProperty::Completed
                                            ))
                                    })
                                    .cloned()
                                    .collect(),
                                component_ids: vec![],
                            },
                        });
                    } else {
                        return Err(ItipError::SenderIsNotParticipant(sender.clone()));
                    }
                }
            }
            ICalendarMethod::Refresh => {
                return organizer_request_full(ical, snapshots, None, false).map(|mut message| {
                    message.to = vec![sender];
                    MergeResult::Message(message)
                });
            }
            _ => return Err(ItipError::UnsupportedMethod(method.clone())),
        }
    } else {
        // Handle organizer updates
        match method {
            ICalendarMethod::Request => {
                let mut is_full_update = false;
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    is_full_update = is_full_update || instance_id == &InstanceId::Main;
                    let itip_component = &itip.components[itip_snapshot.comp_id as usize];

                    if let Some(snapshot) = snapshots.components.get(instance_id) {
                        // Merge instances
                        if itip_snapshot.sequence.unwrap_or_default()
                            >= snapshot.sequence.unwrap_or_default()
                        {
                            let mut changed_entries = itip_snapshot
                                .entries
                                .symmetric_difference(&snapshot.entries)
                                .map(|entry| entry.name.clone())
                                .collect::<AHashSet<_>>();
                            if itip_snapshot.attendees != snapshot.attendees {
                                changed_entries.insert(ICalendarProperty::Attendee);
                            }
                            if itip_snapshot.dtstamp.is_some()
                                && itip_snapshot.dtstamp != snapshot.dtstamp
                            {
                                changed_entries.insert(ICalendarProperty::Dtstamp);
                            }
                            changed_entries.insert(ICalendarProperty::Sequence);

                            if !changed_entries.is_empty() {
                                merge_actions.push(MergeAction::AddEntries {
                                    component_id: snapshot.comp_id,
                                    entries: itip_component
                                        .entries
                                        .iter()
                                        .filter(|entry| changed_entries.contains(&entry.name))
                                        .cloned()
                                        .collect(),
                                });
                                merge_actions.push(MergeAction::RemoveEntries {
                                    component_id: snapshot.comp_id,
                                    entries: changed_entries,
                                });
                            }
                        } else {
                            return Err(ItipError::OutOfSequence);
                        }
                    } else {
                        // Add instance
                        merge_actions.push(MergeAction::AddComponent {
                            component: ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        !matches!(entry.name, ICalendarProperty::Other(_))
                                    })
                                    .cloned()
                                    .collect(),
                                component_ids: vec![],
                            },
                        });
                    }
                }

                if is_full_update {
                    for (instance_id, snapshot) in &snapshots.components {
                        if !itip_snapshots.components.contains_key(instance_id) {
                            // Remove instance
                            merge_actions.push(MergeAction::RemoveComponent {
                                component_id: snapshot.comp_id,
                            });
                        }
                    }
                }
            }
            ICalendarMethod::Add => {
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    if !snapshots.components.contains_key(instance_id) {
                        let itip_component = &itip.components[itip_snapshot.comp_id as usize];
                        merge_actions.push(MergeAction::AddComponent {
                            component: ICalendarComponent {
                                component_type: itip_component.component_type.clone(),
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        !matches!(entry.name, ICalendarProperty::Other(_))
                                    })
                                    .cloned()
                                    .collect(),
                                component_ids: vec![],
                            },
                        });
                    }
                }
            }
            ICalendarMethod::Cancel => {
                for (instance_id, itip_snapshot) in &itip_snapshots.components {
                    if let Some(snapshot) = snapshots.components.get(instance_id) {
                        if itip_snapshot.sequence.unwrap_or_default()
                            >= snapshot.sequence.unwrap_or_default()
                        {
                            // Cancel instance
                            let itip_component = &itip.components[itip_snapshot.comp_id as usize];
                            merge_actions.push(MergeAction::RemoveEntries {
                                component_id: snapshot.comp_id,
                                entries: [
                                    ICalendarProperty::Organizer,
                                    ICalendarProperty::Attendee,
                                    ICalendarProperty::Status,
                                    ICalendarProperty::Sequence,
                                ]
                                .into_iter()
                                .collect(),
                            });
                            merge_actions.push(MergeAction::AddEntries {
                                component_id: snapshot.comp_id,
                                entries: itip_component
                                    .entries
                                    .iter()
                                    .filter(|entry| {
                                        matches!(
                                            entry.name,
                                            ICalendarProperty::Organizer
                                                | ICalendarProperty::Attendee
                                        )
                                    })
                                    .cloned()
                                    .chain([ICalendarEntry {
                                        name: ICalendarProperty::Status,
                                        params: vec![],
                                        values: vec![ICalendarValue::Status(
                                            ICalendarStatus::Cancelled,
                                        )],
                                    }])
                                    .collect(),
                            });
                        } else {
                            return Err(ItipError::OutOfSequence);
                        }
                    }
                }
            }
            _ => return Err(ItipError::UnsupportedMethod(method.clone())),
        }
    }

    if !merge_actions.is_empty() {
        Ok(MergeResult::Actions(merge_actions))
    } else {
        Ok(MergeResult::None)
    }
}

pub fn itip_merge_changes(ical: &mut ICalendar, changes: Vec<MergeAction>) {
    let c = println!("Merging changes: {:?}", changes);

    let mut remove_component_ids = Vec::new();
    for action in changes {
        match action {
            MergeAction::AddEntries {
                component_id,
                entries,
            } => {
                let component = &mut ical.components[component_id as usize];
                component.entries.extend(entries);
            }
            MergeAction::RemoveEntries {
                component_id,
                entries,
            } => {
                let component = &mut ical.components[component_id as usize];
                component
                    .entries
                    .retain(|entry| !entries.contains(&entry.name));
            }
            MergeAction::AddParameters {
                component_id,
                entry_id,
                parameters,
            } => {
                ical.components[component_id as usize].entries[entry_id as usize]
                    .params
                    .extend(parameters);
            }
            MergeAction::RemoveParameters {
                component_id,
                entry_id,
                parameters,
            } => {
                ical.components[component_id as usize].entries[entry_id as usize]
                    .params
                    .retain(|param| !parameters.iter().any(|p| param.matches_name(p)));
            }
            MergeAction::AddComponent { component } => {
                let comp_id = ical.components.len() as u16;
                if let Some(root) = ical
                    .components
                    .get_mut(0)
                    .filter(|c| c.component_type == ICalendarComponentType::VCalendar)
                {
                    root.component_ids.push(comp_id);
                    ical.components.push(component);
                }
            }
            MergeAction::RemoveComponent { component_id } => {
                remove_component_ids.push(component_id);
            }
        }
    }

    if !remove_component_ids.is_empty() {
        ical.remove_component_ids(&remove_component_ids);
    }
}

fn itip_method(ical: &ICalendar) -> Result<&ICalendarMethod, ItipError> {
    let todo = "validate max size of components before saving + max itip message size";
    let todo2 = "make sure root is vcalendar and all components are of the same type";
    ical.components
        .first()
        .and_then(|comp| {
            comp.entries.iter().find_map(|entry| {
                if entry.name == ICalendarProperty::Method {
                    entry.values.first().and_then(|value| {
                        if let ICalendarValue::Method(method) = value {
                            Some(method)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
        })
        .ok_or(ItipError::MissingMethod)
}
