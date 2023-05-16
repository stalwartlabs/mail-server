/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use mail_auth::common::base32::Base32Reader;
use smtp_proto::Response;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::slice::Iter;
use std::{fmt::Write, time::Instant};
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::{
    instant_to_timestamp, Domain, DomainPart, Error, ErrorDetails, HostResponse,
    InstantFromTimestamp, Message, Recipient, Schedule, Status, RCPT_STATUS_CHANGED,
};

pub trait QueueSerializer: Sized {
    fn serialize(&self, buf: &mut String);
    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self>;
}

impl Message {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = String::with_capacity(
            self.return_path.len()
                + self.env_id.as_ref().map_or(0, |e| e.len())
                + (self.domains.len() * 64)
                + (self.recipients.len() * 64)
                + 50,
        );

        // Serialize message properties
        (self.created as usize).serialize(&mut buf);
        self.return_path.serialize(&mut buf);
        (self.env_id.as_deref().unwrap_or_default()).serialize(&mut buf);
        (self.flags as usize).serialize(&mut buf);
        self.priority.serialize(&mut buf);

        // Serialize domains
        let now = Instant::now();
        self.domains.len().serialize(&mut buf);
        for domain in &self.domains {
            domain.domain.serialize(&mut buf);
            (instant_to_timestamp(now, domain.expires) as usize).serialize(&mut buf);
        }

        // Serialize recipients
        self.recipients.len().serialize(&mut buf);
        for rcpt in &self.recipients {
            rcpt.domain_idx.serialize(&mut buf);
            rcpt.address.serialize(&mut buf);
            (rcpt.orcpt.as_deref().unwrap_or_default()).serialize(&mut buf);
        }

        // Serialize domain status
        for (idx, domain) in self.domains.iter().enumerate() {
            domain.serialize(idx, now, &mut buf);
        }

        // Serialize recipient status
        for (idx, rcpt) in self.recipients.iter().enumerate() {
            rcpt.serialize(idx, &mut buf);
        }

        buf.into_bytes()
    }

    pub fn serialize_changes(&mut self) -> Vec<u8> {
        let now = Instant::now();
        let mut buf = String::with_capacity(128);

        for (idx, domain) in self.domains.iter_mut().enumerate() {
            if domain.changed {
                domain.changed = false;
                domain.serialize(idx, now, &mut buf);
            }
        }

        for (idx, rcpt) in self.recipients.iter_mut().enumerate() {
            if rcpt.has_flag(RCPT_STATUS_CHANGED) {
                rcpt.flags &= !RCPT_STATUS_CHANGED;
                rcpt.serialize(idx, &mut buf);
            }
        }

        buf.into_bytes()
    }

    pub async fn from_path(path: PathBuf) -> Result<Self, String> {
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .and_then(|f| f.rsplit_once('.'))
            .map(|(f, _)| f)
            .ok_or_else(|| format!("Invalid queue file name {}", path.display()))?;

        // Decode file name
        let mut id = [0u8; std::mem::size_of::<u64>()];
        let mut size = [0u8; std::mem::size_of::<u32>()];

        for (pos, byte) in Base32Reader::new(filename.as_bytes()).enumerate() {
            match pos {
                0..=7 => {
                    id[pos] = byte;
                }
                8..=11 => {
                    size[pos - 8] = byte;
                }
                _ => {
                    return Err(format!("Invalid queue file name {}", path.display()));
                }
            }
        }

        let id = u64::from_le_bytes(id);
        let size = u32::from_le_bytes(size) as u64;

        // Obtail file size
        let file_size = fs::metadata(&path)
            .await
            .map_err(|err| {
                format!(
                    "Failed to obtain file metadata for {}: {}",
                    path.display(),
                    err
                )
            })?
            .len();
        if size == 0 || size >= file_size {
            return Err(format!(
                "Invalid queue file name size {} for {}",
                size,
                path.display()
            ));
        }
        let mut buf = Vec::with_capacity((file_size - size) as usize);
        let mut file = File::open(&path)
            .await
            .map_err(|err| format!("Failed to open queue file {}: {}", path.display(), err))?;
        file.seek(SeekFrom::Start(size))
            .await
            .map_err(|err| format!("Failed to seek queue file {}: {}", path.display(), err))?;
        file.read_to_end(&mut buf)
            .await
            .map_err(|err| format!("Failed to read queue file {}: {}", path.display(), err))?;

        let mut message = Self::deserialize(&buf)
            .ok_or_else(|| format!("Failed to deserialize metadata for file {}", path.display()))?;
        message.path = path;
        message.size = size as usize;
        message.id = id;
        Ok(message)
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let mut bytes = bytes.iter();
        let created = usize::deserialize(&mut bytes)? as u64;
        let return_path = String::deserialize(&mut bytes)?;
        let return_path_lcase = return_path.to_lowercase();
        let env_id = String::deserialize(&mut bytes)?;

        let mut message = Message {
            id: 0,
            path: PathBuf::new(),
            created,
            return_path_domain: return_path_lcase.domain_part().to_string(),
            return_path_lcase,
            return_path,
            env_id: if !env_id.is_empty() {
                env_id.into()
            } else {
                None
            },
            flags: usize::deserialize(&mut bytes)? as u64,
            priority: i16::deserialize(&mut bytes)?,
            size: 0,
            recipients: vec![],
            domains: vec![],
            queue_refs: vec![],
        };

        // Deserialize domains
        let num_domains = usize::deserialize(&mut bytes)?;
        message.domains = Vec::with_capacity(num_domains);
        for _ in 0..num_domains {
            message.domains.push(Domain {
                domain: String::deserialize(&mut bytes)?,
                expires: Instant::deserialize(&mut bytes)?,
                retry: Schedule::now(),
                notify: Schedule::now(),
                status: Status::Scheduled,
                changed: false,
            });
        }

        // Deserialize recipients
        let num_recipients = usize::deserialize(&mut bytes)?;
        message.recipients = Vec::with_capacity(num_recipients);
        for _ in 0..num_recipients {
            let domain_idx = usize::deserialize(&mut bytes)?;
            let address = String::deserialize(&mut bytes)?;
            let orcpt = String::deserialize(&mut bytes)?;
            message.recipients.push(Recipient {
                domain_idx,
                address_lcase: address.to_lowercase(),
                address,
                status: Status::Scheduled,
                flags: 0,
                orcpt: if !orcpt.is_empty() {
                    orcpt.into()
                } else {
                    None
                },
            });
        }

        // Deserialize status
        while let Some((ch, idx)) = bytes
            .next()
            .and_then(|ch| (ch, usize::deserialize(&mut bytes)?).into())
        {
            match ch {
                b'D' => {
                    if let (Some(domain), Some(retry), Some(notify), Some(status)) = (
                        message.domains.get_mut(idx),
                        Schedule::deserialize(&mut bytes),
                        Schedule::deserialize(&mut bytes),
                        Status::deserialize(&mut bytes),
                    ) {
                        domain.retry = retry;
                        domain.notify = notify;
                        domain.status = status;
                    } else {
                        break;
                    }
                }
                b'R' => {
                    if let (Some(rcpt), Some(flags), Some(status)) = (
                        message.recipients.get_mut(idx),
                        usize::deserialize(&mut bytes),
                        Status::deserialize(&mut bytes),
                    ) {
                        rcpt.flags = flags as u64;
                        rcpt.status = status;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }

        message.into()
    }
}

impl<T: QueueSerializer, E: QueueSerializer> QueueSerializer for Status<T, E> {
    fn serialize(&self, buf: &mut String) {
        match self {
            Status::Scheduled => buf.push('S'),
            Status::Completed(s) => {
                buf.push('C');
                s.serialize(buf);
            }
            Status::TemporaryFailure(s) => {
                buf.push('T');
                s.serialize(buf);
            }
            Status::PermanentFailure(s) => {
                buf.push('F');
                s.serialize(buf);
            }
        }
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match bytes.next()? {
            b'S' => Self::Scheduled.into(),
            b'C' => Self::Completed(T::deserialize(bytes)?).into(),
            b'T' => Self::TemporaryFailure(E::deserialize(bytes)?).into(),
            b'F' => Self::PermanentFailure(E::deserialize(bytes)?).into(),
            _ => None,
        }
    }
}

impl QueueSerializer for Response<String> {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(
            buf,
            "{} {} {} {} {} {}",
            self.code,
            self.esc[0],
            self.esc[1],
            self.esc[2],
            self.message.len(),
            self.message
        );
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        Response {
            code: usize::deserialize(bytes)? as u16,
            esc: [
                usize::deserialize(bytes)? as u8,
                usize::deserialize(bytes)? as u8,
                usize::deserialize(bytes)? as u8,
            ],
            message: String::deserialize(bytes)?,
        }
        .into()
    }
}

impl QueueSerializer for usize {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(buf, "{self} ");
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let mut num = 0;
        loop {
            match bytes.next()? {
                ch @ (b'0'..=b'9') => {
                    num = (num * 10) + (*ch - b'0') as usize;
                }
                b' ' => {
                    return num.into();
                }
                _ => {
                    return None;
                }
            }
        }
    }
}

impl QueueSerializer for i16 {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(buf, "{self} ");
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let mut num = 0;
        let mut mul = 1;
        loop {
            match bytes.next()? {
                ch @ (b'0'..=b'9') => {
                    num = (num * 10) + (*ch - b'0') as i16;
                }
                b' ' => {
                    return (num * mul).into();
                }
                b'-' => {
                    mul = -1;
                }
                _ => {
                    return None;
                }
            }
        }
    }
}

impl QueueSerializer for ErrorDetails {
    fn serialize(&self, buf: &mut String) {
        self.entity.serialize(buf);
        self.details.serialize(buf);
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        ErrorDetails {
            entity: String::deserialize(bytes)?,
            details: String::deserialize(bytes)?,
        }
        .into()
    }
}

impl<T: QueueSerializer> QueueSerializer for HostResponse<T> {
    fn serialize(&self, buf: &mut String) {
        self.hostname.serialize(buf);
        self.response.serialize(buf);
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        HostResponse {
            hostname: T::deserialize(bytes)?,
            response: Response::deserialize(bytes)?,
        }
        .into()
    }
}

impl QueueSerializer for String {
    fn serialize(&self, buf: &mut String) {
        if !self.is_empty() {
            let _ = write!(buf, "{} {}", self.len(), self);
        } else {
            buf.push_str("0 ");
        }
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match usize::deserialize(bytes)? {
            len @ (1..=4096) => {
                String::from_utf8(bytes.take(len).copied().collect::<Vec<_>>()).ok()
            }
            0 => String::new().into(),
            _ => None,
        }
    }
}

impl QueueSerializer for &str {
    fn serialize(&self, buf: &mut String) {
        if !self.is_empty() {
            let _ = write!(buf, "{} {}", self.len(), self);
        } else {
            buf.push_str("0 ");
        }
    }

    fn deserialize(_bytes: &mut Iter<'_, u8>) -> Option<Self> {
        unimplemented!()
    }
}

impl QueueSerializer for Instant {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(buf, "{} ", instant_to_timestamp(Instant::now(), *self),);
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        (usize::deserialize(bytes)? as u64).to_instant().into()
    }
}

impl QueueSerializer for Schedule<u32> {
    fn serialize(&self, buf: &mut String) {
        let _ = write!(
            buf,
            "{} {} ",
            self.inner,
            instant_to_timestamp(Instant::now(), self.due),
        );
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        Schedule {
            inner: usize::deserialize(bytes)? as u32,
            due: Instant::deserialize(bytes)?,
        }
        .into()
    }
}

impl QueueSerializer for Error {
    fn serialize(&self, buf: &mut String) {
        match self {
            Error::DnsError(e) => {
                buf.push('0');
                e.serialize(buf);
            }
            Error::UnexpectedResponse(e) => {
                buf.push('1');
                e.serialize(buf);
            }
            Error::ConnectionError(e) => {
                buf.push('2');
                e.serialize(buf);
            }
            Error::TlsError(e) => {
                buf.push('3');
                e.serialize(buf);
            }
            Error::DaneError(e) => {
                buf.push('4');
                e.serialize(buf);
            }
            Error::MtaStsError(e) => {
                buf.push('5');
                e.serialize(buf);
            }
            Error::RateLimited => {
                buf.push('6');
            }
            Error::ConcurrencyLimited => {
                buf.push('7');
            }
            Error::Io(e) => {
                buf.push('8');
                e.serialize(buf);
            }
        }
    }

    fn deserialize(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match bytes.next()? {
            b'0' => Error::DnsError(String::deserialize(bytes)?).into(),
            b'1' => Error::UnexpectedResponse(HostResponse::deserialize(bytes)?).into(),
            b'2' => Error::ConnectionError(ErrorDetails::deserialize(bytes)?).into(),
            b'3' => Error::TlsError(ErrorDetails::deserialize(bytes)?).into(),
            b'4' => Error::DaneError(ErrorDetails::deserialize(bytes)?).into(),
            b'5' => Error::MtaStsError(String::deserialize(bytes)?).into(),
            b'6' => Error::RateLimited.into(),
            b'7' => Error::ConcurrencyLimited.into(),
            b'8' => Error::Io(String::deserialize(bytes)?).into(),
            _ => None,
        }
    }
}

impl QueueSerializer for () {
    fn serialize(&self, _buf: &mut String) {}

    fn deserialize(_bytes: &mut Iter<'_, u8>) -> Option<Self> {
        Some(())
    }
}

impl Domain {
    fn serialize(&self, idx: usize, now: Instant, buf: &mut String) {
        let _ = write!(
            buf,
            "D{} {} {} {} {} ",
            idx,
            self.retry.inner,
            instant_to_timestamp(now, self.retry.due),
            self.notify.inner,
            instant_to_timestamp(now, self.notify.due)
        );
        self.status.serialize(buf);
    }
}

impl Recipient {
    fn serialize(&self, idx: usize, buf: &mut String) {
        let _ = write!(buf, "R{} {} ", idx, self.flags);
        self.status.serialize(buf);
    }
}
