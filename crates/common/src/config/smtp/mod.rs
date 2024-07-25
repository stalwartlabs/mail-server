/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::{Config, Rate};

pub mod auth;
pub mod queue;
pub mod report;
pub mod resolver;
pub mod session;
pub mod throttle;

use crate::expr::{tokenizer::TokenMap, Expression};

use self::{
    auth::MailAuthConfig, queue::QueueConfig, report::ReportConfig, resolver::Resolvers,
    session::SessionConfig,
};

use super::*;

#[derive(Default, Clone)]
pub struct SmtpConfig {
    pub session: SessionConfig,
    pub queue: QueueConfig,
    pub resolvers: Resolvers,
    pub mail_auth: MailAuthConfig,
    pub report: ReportConfig,
}

#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct Throttle {
    pub id: String,
    pub expr: Expression,
    pub keys: u16,
    pub concurrency: Option<u64>,
    pub rate: Option<Rate>,
}

pub const THROTTLE_RCPT: u16 = 1 << 0;
pub const THROTTLE_RCPT_DOMAIN: u16 = 1 << 1;
pub const THROTTLE_SENDER: u16 = 1 << 2;
pub const THROTTLE_SENDER_DOMAIN: u16 = 1 << 3;
pub const THROTTLE_AUTH_AS: u16 = 1 << 4;
pub const THROTTLE_LISTENER: u16 = 1 << 5;
pub const THROTTLE_MX: u16 = 1 << 6;
pub const THROTTLE_REMOTE_IP: u16 = 1 << 7;
pub const THROTTLE_LOCAL_IP: u16 = 1 << 8;
pub const THROTTLE_HELO_DOMAIN: u16 = 1 << 9;

pub(crate) const RCPT_DOMAIN_VARS: &[u32; 1] = &[V_RECIPIENT_DOMAIN];

pub(crate) const SMTP_EHLO_VARS: &[u32; 8] = &[
    V_LISTENER,
    V_REMOTE_IP,
    V_REMOTE_PORT,
    V_LOCAL_IP,
    V_LOCAL_PORT,
    V_PROTOCOL,
    V_TLS,
    V_HELO_DOMAIN,
];
pub(crate) const SMTP_MAIL_FROM_VARS: &[u32; 10] = &[
    V_LISTENER,
    V_REMOTE_IP,
    V_REMOTE_PORT,
    V_LOCAL_IP,
    V_LOCAL_PORT,
    V_PROTOCOL,
    V_TLS,
    V_SENDER,
    V_SENDER_DOMAIN,
    V_AUTHENTICATED_AS,
];
pub(crate) const SMTP_RCPT_TO_VARS: &[u32; 15] = &[
    V_SENDER,
    V_SENDER_DOMAIN,
    V_RECIPIENTS,
    V_RECIPIENT,
    V_RECIPIENT_DOMAIN,
    V_AUTHENTICATED_AS,
    V_LISTENER,
    V_REMOTE_IP,
    V_REMOTE_PORT,
    V_LOCAL_IP,
    V_LOCAL_PORT,
    V_PROTOCOL,
    V_TLS,
    V_PRIORITY,
    V_HELO_DOMAIN,
];
pub(crate) const SMTP_QUEUE_HOST_VARS: &[u32; 14] = &[
    V_SENDER,
    V_SENDER_DOMAIN,
    V_RECIPIENT_DOMAIN,
    V_RECIPIENT,
    V_RECIPIENTS,
    V_MX,
    V_PRIORITY,
    V_REMOTE_IP,
    V_LOCAL_IP,
    V_QUEUE_RETRY_NUM,
    V_QUEUE_NOTIFY_NUM,
    V_QUEUE_EXPIRES_IN,
    V_QUEUE_LAST_STATUS,
    V_QUEUE_LAST_ERROR,
];
pub(crate) const SMTP_QUEUE_RCPT_VARS: &[u32; 10] = &[
    V_RECIPIENT_DOMAIN,
    V_RECIPIENTS,
    V_SENDER,
    V_SENDER_DOMAIN,
    V_PRIORITY,
    V_QUEUE_RETRY_NUM,
    V_QUEUE_NOTIFY_NUM,
    V_QUEUE_EXPIRES_IN,
    V_QUEUE_LAST_STATUS,
    V_QUEUE_LAST_ERROR,
];
pub(crate) const SMTP_QUEUE_SENDER_VARS: &[u32; 8] = &[
    V_SENDER,
    V_SENDER_DOMAIN,
    V_PRIORITY,
    V_QUEUE_RETRY_NUM,
    V_QUEUE_NOTIFY_NUM,
    V_QUEUE_EXPIRES_IN,
    V_QUEUE_LAST_STATUS,
    V_QUEUE_LAST_ERROR,
];
pub(crate) const SMTP_QUEUE_MX_VARS: &[u32; 11] = &[
    V_RECIPIENT_DOMAIN,
    V_RECIPIENTS,
    V_SENDER,
    V_SENDER_DOMAIN,
    V_PRIORITY,
    V_MX,
    V_QUEUE_RETRY_NUM,
    V_QUEUE_NOTIFY_NUM,
    V_QUEUE_EXPIRES_IN,
    V_QUEUE_LAST_STATUS,
    V_QUEUE_LAST_ERROR,
];

impl SmtpConfig {
    pub async fn parse(config: &mut Config) -> Self {
        Self {
            session: SessionConfig::parse(config),
            queue: QueueConfig::parse(config),
            resolvers: Resolvers::parse(config).await,
            mail_auth: MailAuthConfig::parse(config),
            report: ReportConfig::parse(config),
        }
    }
}
