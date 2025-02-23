/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{Deserialize, Serialize};

use super::PushSubscription;

impl Serialize for PushSubscription {
    fn serialize(self) -> Vec<u8> {
        let todo = 1;
        todo!()
    }
}

impl Deserialize for PushSubscription {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let todo = 1;
        todo!()
    }
}
