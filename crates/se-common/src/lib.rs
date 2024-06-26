/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is not open source software. It must not be modified or distributed without
 * explicit permission from Stalwart Labs Ltd.
 * Unauthorized use, modification, or distribution is strictly prohibited.
 */

use common::Core;

pub trait EnterpriseCore {
    fn is_enterprise_edition(&self) -> bool;
    fn log_license_details(&self);
    fn licensed_accounts(&self) -> u32;
}

impl EnterpriseCore for Core {
    // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
    // Any attempt to modify, bypass, or disable this license validation mechanism
    // constitutes a severe violation of the Stalwart Enterprise License Agreement.
    // Such actions may result in immediate termination of your license, legal action,
    // and substantial financial penalties. Stalwart Labs Ltd. actively monitors for
    // unauthorized modifications and will pursue all available legal remedies against
    // violators to the fullest extent of the law, including but not limited to claims
    // for copyright infringement, breach of contract, and fraud.

    fn is_enterprise_edition(&self) -> bool {
        self.enterprise
            .as_ref()
            .map_or(false, |e| !e.license.is_expired())
    }

    fn licensed_accounts(&self) -> u32 {
        self.enterprise.as_ref().map_or(0, |e| e.license.accounts)
    }

    fn log_license_details(&self) {
        if let Some(enterprise) = &self.enterprise {
            tracing::info!(
                licensed_to = enterprise.license.hostname,
                valid_from = enterprise.license.valid_from,
                valid_to = enterprise.license.valid_to,
                accounts = enterprise.license.accounts,
                "Stalwart Enterprise Edition license key is valid",
            );
        }
    }
}
