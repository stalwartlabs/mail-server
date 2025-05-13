/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::resolver::{Mode, MxPattern, Policy};

pub trait VerifyPolicy {
    fn verify(&self, mx_host: &str) -> bool;
    fn enforce(&self) -> bool;
}

impl VerifyPolicy for Policy {
    fn verify(&self, mx_host: &str) -> bool {
        if self.mode != Mode::None {
            for mx_pattern in &self.mx {
                match mx_pattern {
                    MxPattern::Equals(host) => {
                        if host == mx_host {
                            return true;
                        }
                    }
                    MxPattern::StartsWith(domain) => {
                        if let Some((_, suffix)) = mx_host.split_once('.') {
                            if suffix == domain {
                                return true;
                            }
                        }
                    }
                }
            }

            false
        } else {
            true
        }
    }

    fn enforce(&self) -> bool {
        self.mode == Mode::Enforce
    }
}
