use utils::config::{Config, Rate};

pub mod auth;
pub mod queue;
pub mod report;
pub mod resolver;
pub mod session;
pub mod throttle;

use crate::expr::{if_block::IfBlock, tokenizer::TokenMap, Expression, ExpressionItem, Token};

use self::{
    auth::MailAuthConfig, queue::QueueConfig, report::ReportConfig, resolver::Resolvers,
    session::SessionConfig,
};

pub struct SmtpConfig {
    pub session: SessionConfig,
    pub queue: QueueConfig,
    pub resolvers: Resolvers,
    pub mail_auth: MailAuthConfig,
    pub report: ReportConfig,
}

#[derive(Debug, Default)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct Throttle {
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

pub const V_RECIPIENT: u32 = 0;
pub const V_RECIPIENT_DOMAIN: u32 = 1;
pub const V_SENDER: u32 = 2;
pub const V_SENDER_DOMAIN: u32 = 3;
pub const V_MX: u32 = 4;
pub const V_HELO_DOMAIN: u32 = 5;
pub const V_AUTHENTICATED_AS: u32 = 6;
pub const V_LISTENER: u32 = 7;
pub const V_REMOTE_IP: u32 = 8;
pub const V_LOCAL_IP: u32 = 9;
pub const V_PRIORITY: u32 = 10;

pub const VARIABLES_MAP: &[(&str, u32)] = &[
    ("rcpt", V_RECIPIENT),
    ("rcpt_domain", V_RECIPIENT_DOMAIN),
    ("sender", V_SENDER),
    ("sender_domain", V_SENDER_DOMAIN),
    ("mx", V_MX),
    ("helo_domain", V_HELO_DOMAIN),
    ("authenticated_as", V_AUTHENTICATED_AS),
    ("listener", V_LISTENER),
    ("remote_ip", V_REMOTE_IP),
    ("local_ip", V_LOCAL_IP),
    ("priority", V_PRIORITY),
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

impl TokenMap {
    pub fn with_smtp_variables(mut self, variables: &[u32]) -> Self {
        for (name, idx) in VARIABLES_MAP {
            if variables.contains(idx) {
                self.tokens.insert(name, Token::Variable(*idx));
            }
        }

        self
    }
}

pub(crate) fn parse_server_hostname(config: &mut Config) -> Option<IfBlock> {
    IfBlock::try_parse(
        config,
        "server.hostname",
        &TokenMap::default().with_smtp_variables(&[V_LISTENER, V_REMOTE_IP, V_LOCAL_IP]),
    )
}
