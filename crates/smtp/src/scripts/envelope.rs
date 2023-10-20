/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
