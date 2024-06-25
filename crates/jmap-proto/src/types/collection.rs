/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::{self, Display, Formatter};

use utils::map::bitmap::BitmapItem;

use super::type_state::DataType;

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

impl TryFrom<Collection> for DataType {
    type Error = ();

    fn try_from(value: Collection) -> Result<Self, Self::Error> {
        match value {
            Collection::Email => Ok(DataType::Email),
            Collection::Mailbox => Ok(DataType::Mailbox),
            Collection::Thread => Ok(DataType::Thread),
            Collection::Identity => Ok(DataType::Identity),
            Collection::EmailSubmission => Ok(DataType::EmailSubmission),
            Collection::SieveScript => Ok(DataType::SieveScript),
            Collection::PushSubscription => Ok(DataType::PushSubscription),
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
