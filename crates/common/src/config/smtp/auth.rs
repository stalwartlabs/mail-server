use std::sync::Arc;

use ahash::AHashMap;
use mail_auth::{
    common::crypto::{Ed25519Key, RsaKey, Sha256},
    dkim::Done,
};
use utils::config::utils::{AsKey, ParseValue};

use crate::expr::{self, if_block::IfBlock, Constant, ConstantValue};

pub struct MailAuthConfig {
    pub dkim: DkimAuthConfig,
    pub arc: ArcAuthConfig,
    pub spf: SpfAuthConfig,
    pub dmarc: DmarcAuthConfig,
    pub iprev: IpRevAuthConfig,

    pub signers: AHashMap<String, Arc<DkimSigner>>,
    pub sealers: AHashMap<String, Arc<ArcSealer>>,
}

pub struct DkimAuthConfig {
    pub verify: IfBlock,
    pub sign: IfBlock,
}

pub struct ArcAuthConfig {
    pub verify: IfBlock,
    pub seal: IfBlock,
}

pub struct SpfAuthConfig {
    pub verify_ehlo: IfBlock,
    pub verify_mail_from: IfBlock,
}
pub struct DmarcAuthConfig {
    pub verify: IfBlock,
}

pub struct IpRevAuthConfig {
    pub verify: IfBlock,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum VerifyStrategy {
    #[default]
    Relaxed,
    Strict,
    Disable,
}

pub enum DkimSigner {
    RsaSha256(mail_auth::dkim::DkimSigner<RsaKey<Sha256>, Done>),
    Ed25519Sha256(mail_auth::dkim::DkimSigner<Ed25519Key, Done>),
}

pub enum ArcSealer {
    RsaSha256(mail_auth::arc::ArcSealer<RsaKey<Sha256>, Done>),
    Ed25519Sha256(mail_auth::arc::ArcSealer<Ed25519Key, Done>),
}

impl Default for MailAuthConfig {
    fn default() -> Self {
        Self {
            dkim: DkimAuthConfig {
                verify: IfBlock::new(VerifyStrategy::Relaxed),
                sign: Default::default(),
            },
            arc: ArcAuthConfig {
                verify: IfBlock::new(VerifyStrategy::Relaxed),
                seal: Default::default(),
            },
            spf: SpfAuthConfig {
                verify_ehlo: IfBlock::new(VerifyStrategy::Relaxed),
                verify_mail_from: IfBlock::new(VerifyStrategy::Relaxed),
            },
            dmarc: DmarcAuthConfig {
                verify: IfBlock::new(VerifyStrategy::Relaxed),
            },
            iprev: IpRevAuthConfig {
                verify: IfBlock::new(VerifyStrategy::Relaxed),
            },
            signers: Default::default(),
            sealers: Default::default(),
        }
    }
}

impl<'x> TryFrom<expr::Variable<'x>> for VerifyStrategy {
    type Error = ();

    fn try_from(value: expr::Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            expr::Variable::Integer(c) => match c {
                2 => Ok(VerifyStrategy::Relaxed),
                3 => Ok(VerifyStrategy::Strict),
                4 => Ok(VerifyStrategy::Disable),
                _ => Err(()),
            },
            _ => Err(()),
        }
    }
}

impl From<VerifyStrategy> for Constant {
    fn from(value: VerifyStrategy) -> Self {
        Constant::Integer(match value {
            VerifyStrategy::Relaxed => 2,
            VerifyStrategy::Strict => 3,
            VerifyStrategy::Disable => 4,
        })
    }
}

impl ParseValue for VerifyStrategy {
    fn parse_value(key: impl AsKey, value: &str) -> Result<Self, String> {
        match value {
            "relaxed" => Ok(VerifyStrategy::Relaxed),
            "strict" => Ok(VerifyStrategy::Strict),
            "disable" | "disabled" | "never" | "none" => Ok(VerifyStrategy::Disable),
            _ => Err(format!(
                "Invalid value {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl ConstantValue for VerifyStrategy {}
