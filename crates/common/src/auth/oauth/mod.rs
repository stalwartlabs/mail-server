/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod config;
pub mod crypto;
pub mod introspect;
pub mod oidc;
pub mod registration;
pub mod token;

pub const DEVICE_CODE_LEN: usize = 40;
pub const USER_CODE_LEN: usize = 8;
pub const RANDOM_CODE_LEN: usize = 32;
pub const CLIENT_ID_MAX_LEN: usize = 20;

pub const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No 0, O, I, 1

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GrantType {
    AccessToken,
    RefreshToken,
    LiveTracing,
    LiveMetrics,
}

impl GrantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            GrantType::AccessToken => "access_token",
            GrantType::RefreshToken => "refresh_token",
            GrantType::LiveTracing => "live_tracing",
            GrantType::LiveMetrics => "live_metrics",
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            GrantType::AccessToken => 0,
            GrantType::RefreshToken => 1,
            GrantType::LiveTracing => 2,
            GrantType::LiveMetrics => 3,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(GrantType::AccessToken),
            1 => Some(GrantType::RefreshToken),
            2 => Some(GrantType::LiveTracing),
            3 => Some(GrantType::LiveMetrics),
            _ => None,
        }
    }
}
