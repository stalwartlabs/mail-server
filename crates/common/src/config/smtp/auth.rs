/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Duration};

use ahash::AHashMap;
use mail_auth::{
    common::crypto::{Algorithm, Ed25519Key, HashAlgorithm, RsaKey, Sha256, SigningKey},
    dkim::{Canonicalization, Done},
};
use mail_parser::decoders::base64::base64_decode;
use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

use crate::{
    config::CONNECTION_VARS,
    expr::{self, if_block::IfBlock, tokenizer::TokenMap, Constant, ConstantValue},
};

use super::*;

#[derive(Clone)]
pub struct MailAuthConfig {
    pub dkim: DkimAuthConfig,
    pub arc: ArcAuthConfig,
    pub spf: SpfAuthConfig,
    pub dmarc: DmarcAuthConfig,
    pub iprev: IpRevAuthConfig,

    pub signers: AHashMap<String, Arc<DkimSigner>>,
    pub sealers: AHashMap<String, Arc<ArcSealer>>,
}

#[derive(Clone)]
pub struct DkimAuthConfig {
    pub verify: IfBlock,
    pub sign: IfBlock,
    pub strict: bool,
}

#[derive(Clone)]
pub struct ArcAuthConfig {
    pub verify: IfBlock,
    pub seal: IfBlock,
}

#[derive(Clone)]
pub struct SpfAuthConfig {
    pub verify_ehlo: IfBlock,
    pub verify_mail_from: IfBlock,
}

#[derive(Clone)]
pub struct DmarcAuthConfig {
    pub verify: IfBlock,
}

#[derive(Clone)]
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

#[derive(Debug, Clone)]
pub struct DkimCanonicalization {
    pub headers: Canonicalization,
    pub body: Canonicalization,
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
                verify: IfBlock::new::<VerifyStrategy>("auth.dkim.verify", [], "relaxed"),
                sign: IfBlock::new::<()>(
                    "auth.dkim.sign",
                    [(
                        "is_local_domain('*', sender_domain)",
                        "['rsa-' + sender_domain, 'ed25519-' + sender_domain]",
                    )],
                    "false",
                ),
                strict: true,
            },
            arc: ArcAuthConfig {
                verify: IfBlock::new::<VerifyStrategy>("auth.arc.verify", [], "relaxed"),
                seal: IfBlock::new::<()>(
                    "auth.arc.seal",
                    [],
                    "'rsa-' + key_get('default', 'domain')",
                ),
            },
            spf: SpfAuthConfig {
                verify_ehlo: IfBlock::new::<VerifyStrategy>(
                    "auth.spf.verify.ehlo",
                    [("local_port == 25", "relaxed")],
                    #[cfg(not(feature = "test_mode"))]
                    "disable",
                    #[cfg(feature = "test_mode")]
                    "relaxed",
                ),
                verify_mail_from: IfBlock::new::<VerifyStrategy>(
                    "auth.spf.verify.mail-from",
                    [("local_port == 25", "relaxed")],
                    #[cfg(not(feature = "test_mode"))]
                    "disable",
                    #[cfg(feature = "test_mode")]
                    "relaxed",
                ),
            },
            dmarc: DmarcAuthConfig {
                verify: IfBlock::new::<VerifyStrategy>(
                    "auth.dmarc.verify",
                    [("local_port == 25", "relaxed")],
                    #[cfg(not(feature = "test_mode"))]
                    "disable",
                    #[cfg(feature = "test_mode")]
                    "relaxed",
                ),
            },
            iprev: IpRevAuthConfig {
                verify: IfBlock::new::<VerifyStrategy>(
                    "auth.iprev.verify",
                    [("local_port == 25", "relaxed")],
                    #[cfg(not(feature = "test_mode"))]
                    "disable",
                    #[cfg(feature = "test_mode")]
                    "relaxed",
                ),
            },
            signers: Default::default(),
            sealers: Default::default(),
        }
    }
}

impl MailAuthConfig {
    pub fn parse(config: &mut Config) -> Self {
        let rcpt_vars = TokenMap::default()
            .with_variables(SMTP_RCPT_TO_VARS)
            .with_constants::<VerifyStrategy>();
        let conn_vars = TokenMap::default()
            .with_variables(CONNECTION_VARS)
            .with_constants::<VerifyStrategy>();
        let mut mail_auth = Self::default();

        for (value, key, token_map) in [
            (&mut mail_auth.dkim.verify, "auth.dkim.verify", &rcpt_vars),
            (&mut mail_auth.dkim.sign, "auth.dkim.sign", &rcpt_vars),
            (&mut mail_auth.arc.verify, "auth.arc.verify", &rcpt_vars),
            (&mut mail_auth.arc.seal, "auth.arc.seal", &rcpt_vars),
            (
                &mut mail_auth.spf.verify_ehlo,
                "auth.spf.verify.ehlo",
                &conn_vars,
            ),
            (
                &mut mail_auth.spf.verify_mail_from,
                "auth.spf.verify.mail-from",
                &conn_vars,
            ),
            (&mut mail_auth.dmarc.verify, "auth.dmarc.verify", &rcpt_vars),
            (&mut mail_auth.iprev.verify, "auth.iprev.verify", &conn_vars),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }
        mail_auth.dkim.strict = config
            .property_or_default("auth.dkim.strict", "true")
            .unwrap_or(true);

        // Parse signatures
        for id in config
            .sub_keys("signature", ".algorithm")
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
        {
            let id = id.to_string();
            if let Some((signer, sealer)) = build_signature(config, &id) {
                mail_auth.signers.insert(id.clone(), Arc::new(signer));
                mail_auth.sealers.insert(id, Arc::new(sealer));
            }
        }

        mail_auth
    }
}

fn build_signature(config: &mut Config, id: &str) -> Option<(DkimSigner, ArcSealer)> {
    match config.property_require::<Algorithm>(("signature", id, "algorithm"))? {
        Algorithm::RsaSha256 => {
            let pk = config
                .value_require(("signature", id, "private-key"))?
                .to_string();
            let key = RsaKey::<Sha256>::from_rsa_pem(&pk)
                .or_else(|_| RsaKey::<Sha256>::from_pkcs8_pem(&pk))
                .map_err(|err| {
                    config.new_build_error(
                        ("signature", id, "private-key"),
                        format!("Failed to build RSA key: {err}",),
                    )
                })
                .ok()?;
            let key_clone = RsaKey::<Sha256>::from_rsa_pem(&pk)
                .or_else(|_| RsaKey::<Sha256>::from_pkcs8_pem(&pk))
                .map_err(|err| {
                    config.new_build_error(
                        ("signature", id, "private-key"),
                        format!("Failed to build RSA key: {err}",),
                    )
                })
                .ok()?;
            let (signer, sealer) = parse_signature(config, id, key_clone, key)?;
            (DkimSigner::RsaSha256(signer), ArcSealer::RsaSha256(sealer)).into()
        }
        Algorithm::Ed25519Sha256 => {
            let private_key = parse_pem(config, ("signature", id, "private-key"))?;
            let key = Ed25519Key::from_pkcs8_maybe_unchecked_der(&private_key)
                .map_err(|err| {
                    config.new_build_error(
                        ("signature", id),
                        format!("Failed to build ED25519 key for signature {id:?}: {err}"),
                    )
                })
                .ok()?;
            let key_clone = Ed25519Key::from_pkcs8_maybe_unchecked_der(&private_key)
                .map_err(|err| {
                    config.new_build_error(
                        ("signature", id),
                        format!("Failed to build ED25519 key for signature {id:?}: {err}"),
                    )
                })
                .ok()?;

            let (signer, sealer) = parse_signature(config, id, key_clone, key)?;
            (
                DkimSigner::Ed25519Sha256(signer),
                ArcSealer::Ed25519Sha256(sealer),
            )
                .into()
        }
        Algorithm::RsaSha1 => {
            config.new_build_error(
                ("signature", id),
                format!("Could not build signature {id:?}: SHA1 signatures are deprecated.",),
            );
            None
        }
    }
}

fn parse_pem(config: &mut Config, key: impl AsKey) -> Option<Vec<u8>> {
    if let Some(der) = simple_pem_parse(config.value_require(key.clone())?) {
        Some(der)
    } else {
        config.new_build_error(key, "Failed to base64 decode key.");
        None
    }
}

pub fn simple_pem_parse(contents: &str) -> Option<Vec<u8>> {
    let mut contents = contents.as_bytes().iter().copied();
    let mut base64 = vec![];

    'outer: while let Some(ch) = contents.next() {
        if !ch.is_ascii_whitespace() {
            if ch == b'-' {
                for ch in contents.by_ref() {
                    if ch == b'\n' {
                        break;
                    }
                }
            } else {
                base64.push(ch);
            }

            for ch in contents.by_ref() {
                if ch == b'-' {
                    break 'outer;
                } else if !ch.is_ascii_whitespace() {
                    base64.push(ch);
                }
            }
        }
    }

    base64_decode(&base64)
}

fn parse_signature<T: SigningKey, U: SigningKey<Hasher = Sha256>>(
    config: &mut Config,
    id: &str,
    key_dkim: T,
    key_arc: U,
) -> Option<(
    mail_auth::dkim::DkimSigner<T, Done>,
    mail_auth::arc::ArcSealer<U, Done>,
)> {
    let domain = config
        .value_require(("signature", id, "domain"))?
        .to_string();
    let selector = config
        .value_require(("signature", id, "selector"))?
        .to_string();
    let mut headers = config
        .values(("signature", id, "headers"))
        .filter_map(|(_, v)| {
            if !v.is_empty() {
                v.to_string().into()
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if headers.is_empty() {
        headers = vec![
            "From".to_string(),
            "To".to_string(),
            "Date".to_string(),
            "Subject".to_string(),
            "Message-ID".to_string(),
        ];
    }

    let mut signer = mail_auth::dkim::DkimSigner::from_key(key_dkim)
        .domain(&domain)
        .selector(&selector)
        .headers(headers.clone());
    if !headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("DKIM-Signature"))
    {
        headers.push("DKIM-Signature".to_string());
    }
    let mut sealer = mail_auth::arc::ArcSealer::from_key(key_arc)
        .domain(domain)
        .selector(selector)
        .headers(headers);

    if let Some(c) = config.property::<DkimCanonicalization>(("signature", id, "canonicalization"))
    {
        signer = signer
            .body_canonicalization(c.body)
            .header_canonicalization(c.headers);
        sealer = sealer
            .body_canonicalization(c.body)
            .header_canonicalization(c.headers);
    }

    if let Some(c) = config.property::<Duration>(("signature", id, "expire")) {
        signer = signer.expiration(c.as_secs());
        sealer = sealer.expiration(c.as_secs());
    }

    if let Some(true) = config.property::<bool>(("signature", id, "report")) {
        signer = signer.reporting(true);
    }

    if let Some(auid) = config.property::<String>(("signature", id, "auid")) {
        signer = signer.agent_user_identifier(auid);
    }

    if let Some(atps) = config.property::<String>(("signature", id, "third-party")) {
        signer = signer.atps(atps);
    }

    if let Some(atpsh) = config.property::<HashAlgorithm>(("signature", id, "third-party-algo")) {
        signer = signer.atpsh(atpsh);
    }

    Some((signer, sealer))
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

impl VerifyStrategy {
    #[inline(always)]
    pub fn verify(&self) -> bool {
        matches!(self, VerifyStrategy::Strict | VerifyStrategy::Relaxed)
    }

    #[inline(always)]
    pub fn is_strict(&self) -> bool {
        matches!(self, VerifyStrategy::Strict)
    }
}

impl ParseValue for VerifyStrategy {
    fn parse_value(value: &str) -> Result<Self, String> {
        match value {
            "relaxed" => Ok(VerifyStrategy::Relaxed),
            "strict" => Ok(VerifyStrategy::Strict),
            "disable" | "disabled" | "never" | "none" => Ok(VerifyStrategy::Disable),
            _ => Err(format!("Invalid value {:?}.", value)),
        }
    }
}

impl ConstantValue for VerifyStrategy {
    fn add_constants(token_map: &mut TokenMap) {
        token_map
            .add_constant("relaxed", VerifyStrategy::Relaxed)
            .add_constant("strict", VerifyStrategy::Strict)
            .add_constant("disable", VerifyStrategy::Disable)
            .add_constant("disabled", VerifyStrategy::Disable)
            .add_constant("never", VerifyStrategy::Disable)
            .add_constant("none", VerifyStrategy::Disable);
    }
}

impl ParseValue for DkimCanonicalization {
    fn parse_value(value: &str) -> Result<Self, String> {
        if let Some((headers, body)) = value.split_once('/') {
            Ok(DkimCanonicalization {
                headers: Canonicalization::parse_value(headers.trim())?,
                body: Canonicalization::parse_value(body.trim())?,
            })
        } else {
            let c = Canonicalization::parse_value(value)?;
            Ok(DkimCanonicalization {
                headers: c,
                body: c,
            })
        }
    }
}

impl Default for DkimCanonicalization {
    fn default() -> Self {
        Self {
            headers: Canonicalization::Relaxed,
            body: Canonicalization::Relaxed,
        }
    }
}
