/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::map::vec_map::VecMap;

pub mod index;
pub mod serialize;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EmailSubmission {
    pub email_id: u32,
    pub thread_id: u32,
    pub identity_id: u32,
    pub send_at: u64,
    pub queue_id: Option<u64>,
    pub undo_status: UndoStatus,
    pub envelope: Envelope,
    pub delivery_status: VecMap<String, DeliveryStatus>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub mail_from: Address,
    pub rcpt_to: Vec<Address>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Address {
    pub email: String,
    pub parameters: Option<VecMap<String, Option<String>>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeliveryStatus {
    pub smtp_reply: String,
    pub delivered: Delivered,
    pub displayed: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Delivered {
    Queued,
    Yes,
    No,
    #[default]
    Unknown,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum UndoStatus {
    #[default]
    Pending,
    Final,
    Canceled,
}

impl UndoStatus {
    pub fn parse(s: &str) -> Option<Self> {
        hashify::tiny_map!(s.as_bytes(),
            "pending" => UndoStatus::Pending,
            "final" => UndoStatus::Final,
            "canceled" => UndoStatus::Canceled,
            "cancelled" => UndoStatus::Canceled,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            UndoStatus::Pending => "pending",
            UndoStatus::Final => "final",
            UndoStatus::Canceled => "canceled",
        }
    }

    pub fn as_index(&self) -> &'static str {
        match self {
            UndoStatus::Pending => "p",
            UndoStatus::Final => "f",
            UndoStatus::Canceled => "c",
        }
    }
}

impl Delivered {
    pub fn as_str(&self) -> &'static str {
        match self {
            Delivered::Queued => "queued",
            Delivered::Yes => "yes",
            Delivered::No => "no",
            Delivered::Unknown => "unknown",
        }
    }
}
