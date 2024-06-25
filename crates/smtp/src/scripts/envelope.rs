/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::Envelope;
use smtp_proto::{
    MAIL_BY_NOTIFY, MAIL_BY_RETURN, MAIL_BY_TRACE, MAIL_RET_FULL, MAIL_RET_HDRS, RCPT_NOTIFY_DELAY,
    RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};

use crate::{
    core::{SessionAddress, SessionData},
    queue::DomainPart,
};

impl SessionData {
    pub fn apply_envelope_modification(&mut self, envelope: Envelope, value: String) {
        match envelope {
            Envelope::From => {
                let (address, address_lcase, domain) = if value.contains('@') {
                    let address_lcase = value.to_lowercase();
                    let domain = address_lcase.domain_part().to_string();
                    (value, address_lcase, domain)
                } else if value.is_empty() {
                    (String::new(), String::new(), String::new())
                } else {
                    return;
                };
                if let Some(mail_from) = &mut self.mail_from {
                    mail_from.address = address;
                    mail_from.address_lcase = address_lcase;
                    mail_from.domain = domain;
                } else {
                    self.mail_from = SessionAddress {
                        address,
                        address_lcase,
                        domain,
                        flags: 0,
                        dsn_info: None,
                    }
                    .into();
                }
            }
            Envelope::To => {
                if value.contains('@') {
                    let address_lcase = value.to_lowercase();
                    let domain = address_lcase.domain_part().to_string();
                    if let Some(rcpt_to) = self.rcpt_to.last_mut() {
                        rcpt_to.address = value;
                        rcpt_to.address_lcase = address_lcase;
                        rcpt_to.domain = domain;
                    } else {
                        self.rcpt_to.push(SessionAddress {
                            address: value,
                            address_lcase,
                            domain,
                            flags: 0,
                            dsn_info: None,
                        });
                    }
                }
            }
            Envelope::ByMode => {
                if let Some(mail_from) = &mut self.mail_from {
                    mail_from.flags &= !(MAIL_BY_NOTIFY | MAIL_BY_RETURN);
                    if value == "N" {
                        mail_from.flags |= MAIL_BY_NOTIFY;
                    } else if value == "R" {
                        mail_from.flags |= MAIL_BY_RETURN;
                    }
                }
            }
            Envelope::ByTrace => {
                if let Some(mail_from) = &mut self.mail_from {
                    if value == "T" {
                        mail_from.flags |= MAIL_BY_TRACE;
                    } else {
                        mail_from.flags &= !MAIL_BY_TRACE;
                    }
                }
            }
            Envelope::Notify => {
                if let Some(rcpt_to) = self.rcpt_to.last_mut() {
                    rcpt_to.flags &= !(RCPT_NOTIFY_DELAY
                        | RCPT_NOTIFY_FAILURE
                        | RCPT_NOTIFY_SUCCESS
                        | RCPT_NOTIFY_NEVER);
                    if value == "NEVER" {
                        rcpt_to.flags |= RCPT_NOTIFY_NEVER;
                    } else {
                        for value in value.split(',') {
                            match value.trim() {
                                "SUCCESS" => rcpt_to.flags |= RCPT_NOTIFY_SUCCESS,
                                "FAILURE" => rcpt_to.flags |= RCPT_NOTIFY_FAILURE,
                                "DELAY" => rcpt_to.flags |= RCPT_NOTIFY_DELAY,
                                _ => (),
                            }
                        }
                    }
                }
            }
            Envelope::Ret => {
                if let Some(mail_from) = &mut self.mail_from {
                    mail_from.flags &= !(MAIL_RET_FULL | MAIL_RET_HDRS);
                    if value == "FULL" {
                        mail_from.flags |= MAIL_RET_FULL;
                    } else if value == "HDRS" {
                        mail_from.flags |= MAIL_RET_HDRS;
                    }
                }
            }
            Envelope::Orcpt => {
                if let Some(rcpt_to) = self.rcpt_to.last_mut() {
                    rcpt_to.dsn_info = value.into();
                }
            }
            Envelope::Envid => {
                if let Some(mail_from) = &mut self.mail_from {
                    mail_from.dsn_info = value.into();
                }
            }
            Envelope::ByTimeAbsolute | Envelope::ByTimeRelative => (),
        }
    }
}
