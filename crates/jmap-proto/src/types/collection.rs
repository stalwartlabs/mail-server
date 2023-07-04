/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use std::fmt::{self, Display, Formatter};

use utils::map::bitmap::BitmapItem;

use super::type_state::TypeState;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum Collection {
    Email = 0,
    Mailbox = 1,
    Thread = 2,
    Identity = 3,
    EmailSubmission = 4,
    SieveScript = 5,
    PushSubscription = 6,
    Principal = 7,
    None = 8,
}

impl From<u8> for Collection {
    fn from(v: u8) -> Self {
        match v {
            0 => Collection::Email,
            1 => Collection::Mailbox,
            2 => Collection::Thread,
            3 => Collection::Identity,
            4 => Collection::EmailSubmission,
            5 => Collection::SieveScript,
            6 => Collection::PushSubscription,
            7 => Collection::Principal,
            _ => Collection::None,
        }
    }
}

impl From<u64> for Collection {
    fn from(v: u64) -> Self {
        match v {
            0 => Collection::Email,
            1 => Collection::Mailbox,
            2 => Collection::Thread,
            3 => Collection::Identity,
            4 => Collection::EmailSubmission,
            5 => Collection::SieveScript,
            6 => Collection::PushSubscription,
            7 => Collection::Principal,
            _ => Collection::None,
        }
    }
}

impl From<Collection> for u8 {
    fn from(v: Collection) -> Self {
        v as u8
    }
}

impl From<Collection> for u64 {
    fn from(collection: Collection) -> u64 {
        collection as u64
    }
}

impl TryFrom<Collection> for TypeState {
    type Error = ();

    fn try_from(value: Collection) -> Result<Self, Self::Error> {
        match value {
            Collection::Email => Ok(TypeState::Email),
            Collection::Mailbox => Ok(TypeState::Mailbox),
            Collection::Thread => Ok(TypeState::Thread),
            Collection::Identity => Ok(TypeState::Identity),
            Collection::EmailSubmission => Ok(TypeState::EmailSubmission),
            _ => Err(()),
        }
    }
}

impl Display for Collection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Collection::PushSubscription => write!(f, "pushSubscription"),
            Collection::Email => write!(f, "email"),
            Collection::Mailbox => write!(f, "mailbox"),
            Collection::Thread => write!(f, "thread"),
            Collection::Identity => write!(f, "identity"),
            Collection::EmailSubmission => write!(f, "emailSubmission"),
            Collection::SieveScript => write!(f, "sieveScript"),
            Collection::Principal => write!(f, "principal"),
            Collection::None => write!(f, ""),
        }
    }
}

impl BitmapItem for Collection {
    fn max() -> u64 {
        Collection::None as u64
    }

    fn is_valid(&self) -> bool {
        !matches!(self, Collection::None)
    }
}
