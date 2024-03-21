use std::{net::SocketAddr, time::Duration};

use crate::expr::if_block::IfBlock;

use super::Throttle;

pub struct SessionConfig {
    pub timeout: IfBlock,
    pub duration: IfBlock,
    pub transfer_limit: IfBlock,
    pub throttle: SessionThrottle,

    pub connect: Connect,
    pub ehlo: Ehlo,
    pub auth: Auth,
    pub mail: Mail,
    pub rcpt: Rcpt,
    pub data: Data,
    pub extensions: Extensions,
}

pub struct SessionThrottle {
    pub connect: Vec<Throttle>,
    pub mail_from: Vec<Throttle>,
    pub rcpt_to: Vec<Throttle>,
}

pub struct Connect {
    pub script: IfBlock,
}

pub struct Ehlo {
    pub script: IfBlock,
    pub require: IfBlock,
    pub reject_non_fqdn: IfBlock,
}

pub struct Extensions {
    pub pipelining: IfBlock,
    pub chunking: IfBlock,
    pub requiretls: IfBlock,
    pub dsn: IfBlock,
    pub vrfy: IfBlock,
    pub expn: IfBlock,
    pub no_soliciting: IfBlock,
    pub future_release: IfBlock,
    pub deliver_by: IfBlock,
    pub mt_priority: IfBlock,
}

pub struct Auth {
    pub directory: IfBlock,
    pub mechanisms: IfBlock,
    pub require: IfBlock,
    pub allow_plain_text: IfBlock,
    pub must_match_sender: IfBlock,
    pub errors_max: IfBlock,
    pub errors_wait: IfBlock,
}

pub struct Mail {
    pub script: IfBlock,
    pub rewrite: IfBlock,
}

pub struct Rcpt {
    pub script: IfBlock,
    pub relay: IfBlock,
    pub directory: IfBlock,
    pub rewrite: IfBlock,

    // Errors
    pub errors_max: IfBlock,
    pub errors_wait: IfBlock,

    // Limits
    pub max_recipients: IfBlock,

    // Catch-all and subadressing
    pub catch_all: AddressMapping,
    pub subaddressing: AddressMapping,
}

#[derive(Debug, Default)]
pub enum AddressMapping {
    Enable,
    Custom(IfBlock),
    #[default]
    Disable,
}

pub struct Data {
    pub script: IfBlock,
    pub pipe_commands: Vec<Pipe>,
    pub milters: Vec<Milter>,

    // Limits
    pub max_messages: IfBlock,
    pub max_message_size: IfBlock,
    pub max_received_headers: IfBlock,

    // Headers
    pub add_received: IfBlock,
    pub add_received_spf: IfBlock,
    pub add_return_path: IfBlock,
    pub add_auth_results: IfBlock,
    pub add_message_id: IfBlock,
    pub add_date: IfBlock,
}

pub struct Pipe {
    pub command: IfBlock,
    pub arguments: IfBlock,
    pub timeout: IfBlock,
}

pub struct Milter {
    pub enable: IfBlock,
    pub addrs: Vec<SocketAddr>,
    pub hostname: String,
    pub port: u16,
    pub timeout_connect: Duration,
    pub timeout_command: Duration,
    pub timeout_data: Duration,
    pub tls: bool,
    pub tls_allow_invalid_certs: bool,
    pub tempfail_on_error: bool,
    pub max_frame_len: usize,
    pub protocol_version: MilterVersion,
    pub flags_actions: Option<u32>,
    pub flags_protocol: Option<u32>,
}

#[derive(Clone, Copy)]
pub enum MilterVersion {
    V2,
    V6,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: IfBlock::new(Duration::from_secs(15 * 60)),
            duration: IfBlock::new(Duration::from_secs(5 * 60)),
            transfer_limit: IfBlock::new(250 * 1024 * 1024),
            throttle: SessionThrottle {
                connect: Default::default(),
                mail_from: Default::default(),
                rcpt_to: Default::default(),
            },
            connect: Connect {
                script: Default::default(),
            },
            ehlo: Ehlo {
                script: Default::default(),
                require: IfBlock::new(true),
                reject_non_fqdn: IfBlock::new(true),
            },
            auth: Auth {
                directory: Default::default(),
                mechanisms: Default::default(),
                require: IfBlock::new(false),
                allow_plain_text: IfBlock::new(false),
                must_match_sender: IfBlock::new(true),
                errors_max: IfBlock::new(3),
                errors_wait: IfBlock::new(Duration::from_secs(30)),
            },
            mail: Mail {
                script: Default::default(),
                rewrite: Default::default(),
            },
            rcpt: Rcpt {
                script: Default::default(),
                relay: IfBlock::new(false),
                directory: Default::default(),
                rewrite: Default::default(),
                errors_max: IfBlock::new(10),
                errors_wait: IfBlock::new(Duration::from_secs(30)),
                max_recipients: IfBlock::new(100),
                catch_all: AddressMapping::Disable,
                subaddressing: AddressMapping::Disable,
            },
            data: Data {
                script: Default::default(),
                pipe_commands: Default::default(),
                milters: Default::default(),
                max_messages: IfBlock::new(10),
                max_message_size: IfBlock::new(25 * 1024 * 1024),
                max_received_headers: IfBlock::new(50),
                add_received: IfBlock::new(true),
                add_received_spf: IfBlock::new(true),
                add_return_path: IfBlock::new(true),
                add_auth_results: IfBlock::new(true),
                add_message_id: IfBlock::new(true),
                add_date: IfBlock::new(true),
            },
            extensions: Extensions {
                pipelining: IfBlock::new(true),
                chunking: IfBlock::new(true),
                requiretls: IfBlock::new(true),
                dsn: IfBlock::new(false),
                vrfy: IfBlock::new(false),
                expn: IfBlock::new(false),
                no_soliciting: IfBlock::new(false),
                future_release: Default::default(),
                deliver_by: Default::default(),
                mt_priority: Default::default(),
            },
        }
    }
}
