/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Task;
use calcard::{
    common::timezone::Tz,
    icalendar::{ArchivedICalendarParameter, ArchivedICalendarProperty},
};
use chrono::{DateTime, Locale};
use common::{
    DEFAULT_LOGO, Server,
    config::groupware::CalendarTemplateVariable,
    i18n,
    listener::{ServerInstance, stream::NullIo},
};
use directory::Permission;
use groupware::calendar::{CalendarEvent, alarm::CalendarAlarm};
use jmap_proto::types::collection::Collection;
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, content_type::ContentType},
    mime::{BodyPart, MimePart},
};
use mail_parser::decoders::html::html_to_text;
use smtp::core::{Session, SessionData};
use smtp_proto::{MailFrom, RcptTo};
use std::{str::FromStr, sync::Arc};
use store::write::{BatchBuilder, now};
use trc::{AddContext, TaskQueueEvent};
use utils::{sanitize_email, template::Variables};

pub trait SendAlarmTask: Sync + Send {
    fn send_alarm(
        &self,
        task: &Task,
        alarm: &CalendarAlarm,
        server_instance: Arc<ServerInstance>,
    ) -> impl Future<Output = bool> + Send;
}

impl SendAlarmTask for Server {
    async fn send_alarm(
        &self,
        task: &Task,
        alarm: &CalendarAlarm,
        server_instance: Arc<ServerInstance>,
    ) -> bool {
        match send_alarm(self, task, alarm, server_instance).await {
            Ok(result) => result,
            Err(err) => {
                trc::error!(
                    err.account_id(task.account_id)
                        .document_id(task.document_id)
                        .caused_by(trc::location!())
                        .details("Failed to process alarm")
                );
                false
            }
        }
    }
}

async fn send_alarm(
    server: &Server,
    task: &Task,
    alarm: &CalendarAlarm,
    server_instance: Arc<ServerInstance>,
) -> trc::Result<bool> {
    // Obtain access token
    let access_token = server
        .get_access_token(task.account_id)
        .await
        .caused_by(trc::location!())?;

    if !access_token.has_permission(Permission::CalendarAlarms) {
        trc::event!(
            Calendar(trc::CalendarEvent::AlarmSkipped),
            Reason = "Account does not have permission to send calendar alarms",
            AccountId = task.account_id,
            DocumentId = task.document_id,
        );
        return Ok(true);
    } else if access_token.emails.is_empty() {
        trc::event!(
            Calendar(trc::CalendarEvent::AlarmFailed),
            Reason = "Account does not have any email addresses",
            AccountId = task.account_id,
            DocumentId = task.document_id,
        );
        return Ok(true);
    }

    // Fetch event
    let Some(event_) = server
        .get_archive(task.account_id, Collection::CalendarEvent, task.document_id)
        .await
        .caused_by(trc::location!())?
    else {
        trc::event!(
            TaskQueue(TaskQueueEvent::MetadataNotFound),
            Details = "Calendar Event metadata not found",
            AccountId = task.account_id,
            DocumentId = task.document_id,
        );

        return Ok(true);
    };

    // Unarchive event
    let event = event_
        .unarchive::<CalendarEvent>()
        .caused_by(trc::location!())?;
    let (Some(event_component), Some(alarm_component)) = (
        event.data.event.components.get(alarm.event_id as usize),
        event.data.event.components.get(alarm.alarm_id as usize),
    ) else {
        trc::event!(
            TaskQueue(TaskQueueEvent::MetadataNotFound),
            Details = "Calendar Alarm component not found",
            AccountId = task.account_id,
            DocumentId = task.document_id,
        );
        return Ok(true);
    };

    // Build webcal URI
    let webcal_uri = match event.webcal_uri(server, &access_token).await {
        Ok(uri) => uri,
        Err(err) => {
            trc::error!(
                err.account_id(task.account_id)
                    .document_id(task.document_id)
                    .caused_by(trc::location!())
                    .details("Failed to generate webcal URI")
            );
            String::from("#")
        }
    };

    // Obtain alarm details
    let mut summary = None;
    let mut description = None;
    let mut rcpt_to = None;
    let mut location = None;
    let mut organizer = None;
    let mut guests = vec![];

    for entry in alarm_component.entries.iter() {
        match &entry.name {
            ArchivedICalendarProperty::Summary => {
                summary = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Description => {
                description = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Attendee => {
                rcpt_to = entry
                    .values
                    .first()
                    .and_then(|v| v.as_text())
                    .map(|v| v.strip_prefix("mailto:").unwrap_or(v))
                    .and_then(sanitize_email);
            }
            _ => {}
        }
    }

    for entry in event_component.entries.iter() {
        match &entry.name {
            ArchivedICalendarProperty::Summary if summary.is_none() => {
                summary = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Description if description.is_none() => {
                description = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Location => {
                location = entry.values.first().and_then(|v| v.as_text());
            }
            ArchivedICalendarProperty::Organizer | ArchivedICalendarProperty::Attendee => {
                let email = entry
                    .values
                    .first()
                    .and_then(|v| v.as_text())
                    .map(|v| v.strip_prefix("mailto:").unwrap_or(v));
                let name = entry.params.iter().find_map(|param| {
                    if let ArchivedICalendarParameter::Cn(name) = param {
                        Some(name.as_str())
                    } else {
                        None
                    }
                });

                if email.is_some() || name.is_some() {
                    if matches!(entry.name, ArchivedICalendarProperty::Organizer) {
                        organizer = Some((email, name));
                    } else {
                        guests.push((email, name));
                    }
                }
            }
            _ => {}
        }
    }

    // Validate recipient
    let account_main_email = access_token.emails.first().unwrap();
    let account_main_domain = account_main_email.rsplit('@').next().unwrap_or("localhost");
    let rcpt_to = if let Some(rcpt_to) = rcpt_to {
        if server.core.groupware.alarms_allow_external_recipients
            || access_token.emails.iter().any(|email| email == &rcpt_to)
        {
            rcpt_to
        } else {
            trc::event!(
                Calendar(trc::CalendarEvent::AlarmRecipientOverride),
                Reason = "External recipient not allowed for calendar alarms",
                Details = rcpt_to,
                AccountId = task.account_id,
                DocumentId = task.document_id,
            );

            account_main_email.to_string()
        }
    } else {
        account_main_email.to_string()
    };

    // Build message body
    #[cfg(feature = "enterprise")]
    let template = server
        .core
        .enterprise
        .as_ref()
        .and_then(|e| e.template_calendar_alarm.as_ref())
        .unwrap_or(&server.core.groupware.alarms_template);
    #[cfg(not(feature = "enterprise"))]
    let template = &server.core.groupware.alarms_template;
    let locale = i18n::locale_or_default(access_token.locale.as_deref().unwrap_or("en"));
    let chrono_locale = access_token
        .locale
        .as_deref()
        .and_then(|locale| Locale::from_str(locale).ok())
        .unwrap_or(Locale::en_US);
    let start = format!(
        "{} ({})",
        DateTime::from_timestamp(alarm.event_start, 0)
            .unwrap_or_default()
            .format_localized(locale.calendar_date_template, chrono_locale),
        Tz::from_id(alarm.event_start_tz).unwrap_or(Tz::UTC).name()
    );
    let end = format!(
        "{} ({})",
        DateTime::from_timestamp(alarm.event_end, 0)
            .unwrap_or_default()
            .format_localized(locale.calendar_date_template, chrono_locale),
        Tz::from_id(alarm.event_end_tz).unwrap_or(Tz::UTC).name()
    );
    let subject = format!(
        "{}: {} @ {}",
        locale.calendar_alarm_subject_prefix,
        summary.or(description).unwrap_or("No Subject"),
        start
    );
    let organizer = organizer
        .map(|(email, name)| match (email, name) {
            (Some(email), Some(name)) => format!("{} <{}>", name, email),
            (Some(email), None) => email.to_string(),
            (None, Some(name)) => name.to_string(),
            _ => unreachable!(),
        })
        .unwrap_or_else(|| access_token.name.clone());
    let logo_cid = format!("logo.{}@{account_main_domain}", now());
    let mut variables = Variables::new();
    variables.insert_single(CalendarTemplateVariable::PageTitle, subject.as_str());
    variables.insert_single(
        CalendarTemplateVariable::Header,
        locale.calendar_alarm_header,
    );
    variables.insert_single(
        CalendarTemplateVariable::Footer,
        locale.calendar_alarm_footer,
    );
    variables.insert_single(
        CalendarTemplateVariable::ActionName,
        locale.calendar_alarm_open,
    );
    variables.insert_single(CalendarTemplateVariable::ActionUrl, webcal_uri.as_str());
    variables.insert_single(
        CalendarTemplateVariable::AttendeesTitle,
        locale.calendar_attendees,
    );
    variables.insert_single(
        CalendarTemplateVariable::EventTitle,
        summary.unwrap_or_default(),
    );
    variables.insert_single(CalendarTemplateVariable::LogoCid, logo_cid.as_str());
    if let Some(description) = description {
        variables.insert_single(CalendarTemplateVariable::EventDescription, description);
    }
    variables.insert_block(
        CalendarTemplateVariable::EventDetails,
        [
            Some([
                (CalendarTemplateVariable::Key, locale.calendar_start),
                (CalendarTemplateVariable::Value, start.as_str()),
            ]),
            Some([
                (CalendarTemplateVariable::Key, locale.calendar_end),
                (CalendarTemplateVariable::Value, end.as_str()),
            ]),
            location.map(|location| {
                [
                    (CalendarTemplateVariable::Key, locale.calendar_location),
                    (CalendarTemplateVariable::Value, location),
                ]
            }),
            Some([
                (CalendarTemplateVariable::Key, locale.calendar_organizer),
                (CalendarTemplateVariable::Value, organizer.as_str()),
            ]),
        ]
        .into_iter()
        .flatten(),
    );
    if !guests.is_empty() {
        variables.insert_block(
            CalendarTemplateVariable::Attendees,
            guests.into_iter().map(|(email, name)| {
                [
                    (CalendarTemplateVariable::Key, name.unwrap_or_default()),
                    (CalendarTemplateVariable::Value, email.unwrap_or_default()),
                ]
            }),
        );
    }
    let html_body = template.eval(&variables);
    let txt_body = html_to_text(&html_body);

    // Obtain logo image
    let logo = match server.logo_resource(account_main_domain).await {
        Ok(logo) => logo,
        Err(err) => {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to fetch logo image")
            );
            None
        }
    };
    let (logo_content_type, logo_contents) = if let Some(logo) = &logo {
        (logo.content_type.as_ref(), logo.contents.as_slice())
    } else {
        ("image/svg+xml", DEFAULT_LOGO.as_bytes())
    };

    // Build message
    let mail_from = if let Some(from_email) = &server.core.groupware.alarms_from_email {
        from_email.to_string()
    } else {
        format!("calendar-notification@{account_main_domain}",)
    };
    let message = MessageBuilder::new()
        .from((
            server.core.groupware.alarms_from_name.as_str(),
            mail_from.as_str(),
        ))
        .header("To", HeaderType::Text(rcpt_to.as_str().into()))
        .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
        .header(
            "Reply-To",
            HeaderType::Text(account_main_email.as_str().into()),
        )
        .subject(subject)
        .body(MimePart::new(
            ContentType::new("multipart/mixed"),
            BodyPart::Multipart(vec![
                MimePart::new(
                    ContentType::new("multipart/alternative"),
                    BodyPart::Multipart(vec![
                        MimePart::new(
                            ContentType::new("text/plain"),
                            BodyPart::Text(txt_body.into()),
                        ),
                        MimePart::new(
                            ContentType::new("text/html"),
                            BodyPart::Text(html_body.into()),
                        ),
                    ]),
                ),
                MimePart::new(
                    ContentType::new(logo_content_type),
                    BodyPart::Binary(logo_contents.into()),
                )
                .inline()
                .cid(logo_cid),
            ]),
        ))
        .write_to_vec()
        .unwrap_or_default();

    // Send message
    let server_ = server.clone();
    let mail_from = account_main_email.clone();
    let result = tokio::spawn(async move {
        let mut session = Session::<NullIo>::local(
            server_,
            server_instance,
            SessionData::local(access_token, None, vec![], vec![], 0),
        );

        // MAIL FROM
        let _ = session
            .handle_mail_from(MailFrom {
                address: mail_from,
                ..Default::default()
            })
            .await;
        if let Some(error) = session.has_failed() {
            return Err(format!("Server rejected MAIL-FROM: {}", error.trim()));
        }

        // RCPT TO
        let _ = session
            .handle_rcpt_to(RcptTo {
                address: rcpt_to,
                ..Default::default()
            })
            .await;
        if let Some(error) = session.has_failed() {
            return Err(format!("Server rejected RCPT-TO: {}", error.trim()));
        }

        // DATA
        session.data.message = message;
        let response = session.queue_message().await;
        if let smtp::core::State::Accepted(queue_id) = session.state {
            Ok(queue_id)
        } else {
            Err(format!(
                "Server rejected DATA: {}",
                std::str::from_utf8(&response).unwrap().trim()
            ))
        }
    })
    .await;

    match result {
        Ok(Ok(queue_id)) => {
            trc::event!(
                Calendar(trc::CalendarEvent::AlarmSent),
                AccountId = task.account_id,
                DocumentId = task.document_id,
                QueueId = queue_id,
            );
        }
        Ok(Err(err)) => {
            trc::event!(
                Calendar(trc::CalendarEvent::AlarmFailed),
                AccountId = task.account_id,
                DocumentId = task.document_id,
                Reason = err,
            );
        }
        Err(_) => {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Join Error",
                AccountId = task.account_id,
                DocumentId = task.document_id,
                CausedBy = trc::location!(),
            );
            return Ok(false);
        }
    }

    // Find next alarm time and write to task queue
    let now = now() as i64;
    if let Some(next_alarm) =
        event
            .data
            .next_alarm(now, Default::default())
            .and_then(|next_alarm| {
                // Verify minimum interval
                let max_next_alarm = now + server.core.groupware.alarms_minimum_interval;
                if next_alarm.alarm_time < max_next_alarm {
                    trc::event!(
                        Calendar(trc::CalendarEvent::AlarmSkipped),
                        Reason = "Next alarm skipped due to minimum interval",
                        Details = next_alarm.alarm_time - now,
                        AccountId = task.account_id,
                        DocumentId = task.document_id,
                    );
                    event.data.next_alarm(max_next_alarm, Default::default())
                } else {
                    Some(next_alarm)
                }
            })
    {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(task.account_id)
            .with_collection(Collection::CalendarEvent)
            .update_document(task.document_id);
        next_alarm.write_task(&mut batch);
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(true)
}
