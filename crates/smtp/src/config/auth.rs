/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{sync::Arc, time::Duration};

use mail_auth::{
    common::crypto::{Algorithm, Ed25519Key, HashAlgorithm, RsaKey, Sha256, SigningKey},
    dkim::{Canonicalization, Done},
};
use mail_parser::decoders::base64::base64_decode;
use utils::{
    config::{
        if_block::IfBlock,
        utils::{AsKey, ConstantValue, ParseValue},
        Config,
    },
    expr::{self, Constant, Token},
};

use crate::core::eval::*;

use super::{
    map_expr_token, ArcAuthConfig, ArcSealer, ConfigContext, DkimAuthConfig, DkimCanonicalization,
    DkimSigner, DmarcAuthConfig, IpRevAuthConfig, MailAuthConfig, SpfAuthConfig, VerifyStrategy,
};

pub trait ConfigAuth {
    fn parse_mail_auth(&self) -> super::Result<MailAuthConfig>;
    fn parse_signatures(&self, ctx: &mut ConfigContext) -> super::Result<()>;
}

impl ConfigAuth for Config {
    fn parse_mail_auth(&self) -> super::Result<MailAuthConfig> {
        let fn_sender_keys = |name: &str| -> super::Result<Token> {
            map_expr_token::<VerifyStrategy>(
                name,
                &[
                    V_SENDER,
                    V_SENDER_DOMAIN,
                    V_PRIORITY,
                    V_AUTHENTICATED_AS,
                    V_LISTENER,
                    V_REMOTE_IP,
                    V_LOCAL_IP,
                ],
            )
        };
        let fn_conn_keys = |name: &str| -> super::Result<Token> {
            map_expr_token::<VerifyStrategy>(name, &[V_LISTENER, V_REMOTE_IP, V_LOCAL_IP])
        };

        Ok(MailAuthConfig {
            dkim: DkimAuthConfig {
                verify: self
                    .parse_if_block("auth.dkim.verify", fn_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
                sign: self
                    .parse_if_block("auth.dkim.sign", fn_sender_keys)?
                    .unwrap_or_default(),
            },
            arc: ArcAuthConfig {
                verify: self
                    .parse_if_block("auth.arc.verify", fn_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
                seal: self
                    .parse_if_block("auth.arc.seal", fn_sender_keys)?
                    .unwrap_or_default(),
            },
            spf: SpfAuthConfig {
                verify_ehlo: self
                    .parse_if_block("auth.spf.verify.ehlo", fn_conn_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
                verify_mail_from: self
                    .parse_if_block("auth.spf.verify.mail-from", fn_conn_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
            },
            dmarc: DmarcAuthConfig {
                verify: self
                    .parse_if_block("auth.dmarc.verify", fn_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
            },
            iprev: IpRevAuthConfig {
                verify: self
                    .parse_if_block("auth.iprev.verify", fn_conn_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
            },
        })
    }

    #[allow(clippy::type_complexity)]
    fn parse_signatures(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("signature", ".algorithm") {
            let (signer, sealer) =
                match self.property_require::<Algorithm>(("signature", id, "algorithm"))? {
                    Algorithm::RsaSha256 => {
                        let pk = self.value_require(("signature", id, "private-key"))?;
                        let key = RsaKey::<Sha256>::from_rsa_pem(pk)
                            .or_else(|_| RsaKey::<Sha256>::from_pkcs8_pem(pk))
                            .map_err(|err| {
                                format!(
                                    "Failed to build RSA key for {}: {}",
                                    ("signature", id, "private-key",).as_key(),
                                    err
                                )
                            })?;
                        let key_clone = RsaKey::<Sha256>::from_rsa_pem(pk)
                            .or_else(|_| RsaKey::<Sha256>::from_pkcs8_pem(pk))
                            .map_err(|err| {
                                format!(
                                    "Failed to build RSA key for {}: {}",
                                    ("signature", id, "private-key",).as_key(),
                                    err
                                )
                            })?;
                        let (signer, sealer) = parse_signature(self, id, key_clone, key)?;
                        (DkimSigner::RsaSha256(signer), ArcSealer::RsaSha256(sealer))
                    }
                    Algorithm::Ed25519Sha256 => {
                        let mut public_key = vec![];
                        let mut private_key = vec![];

                        for (key, key_bytes) in [
                            (("signature", id, "public-key"), &mut public_key),
                            (("signature", id, "private-key"), &mut private_key),
                        ] {
                            let mut contents = self.value_require(key)?.as_bytes().iter().copied();
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

                            *key_bytes = base64_decode(&base64).ok_or_else(|| {
                                format!("Failed to base64 decode key for {}.", key.as_key(),)
                            })?;
                        }

                        let key = Ed25519Key::from_pkcs8_maybe_unchecked_der(&private_key)
                            .or_else(|_| {
                                Ed25519Key::from_seed_and_public_key(&private_key, &public_key)
                            })
                            .map_err(|err| {
                                format!("Failed to build ED25519 key for signature {id:?}: {err}")
                            })?;
                        let key_clone = Ed25519Key::from_pkcs8_maybe_unchecked_der(&private_key)
                            .or_else(|_| {
                                Ed25519Key::from_seed_and_public_key(&private_key, &public_key)
                            })
                            .map_err(|err| {
                                format!("Failed to build ED25519 key for signature {id:?}: {err}")
                            })?;

                        let (signer, sealer) = parse_signature(self, id, key_clone, key)?;
                        (
                            DkimSigner::Ed25519Sha256(signer),
                            ArcSealer::Ed25519Sha256(sealer),
                        )
                    }
                    Algorithm::RsaSha1 => {
                        return Err(format!(
                            "Could not build signature {id:?}: SHA1 signatures are deprecated.",
                        ))
                    }
                };
            ctx.signers.insert(id.to_string(), Arc::new(signer));
            ctx.sealers.insert(id.to_string(), Arc::new(sealer));
        }

        Ok(())
    }
}

fn parse_signature<T: SigningKey, U: SigningKey<Hasher = Sha256>>(
    config: &Config,
    id: &str,
    key_dkim: T,
    key_arc: U,
) -> super::Result<(
    mail_auth::dkim::DkimSigner<T, Done>,
    mail_auth::arc::ArcSealer<U, Done>,
)> {
    let domain = config.value_require(("signature", id, "domain"))?;
    let selector = config.value_require(("signature", id, "selector"))?;
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
        .domain(domain)
        .selector(selector)
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

    if let Some(c) =
        config.property::<DkimCanonicalization>(("signature", id, "canonicalization"))?
    {
        signer = signer
            .body_canonicalization(c.body)
            .header_canonicalization(c.headers);
        sealer = sealer
            .body_canonicalization(c.body)
            .header_canonicalization(c.headers);
    }

    if let Some(c) = config.property::<Duration>(("signature", id, "expire"))? {
        signer = signer.expiration(c.as_secs());
        sealer = sealer.expiration(c.as_secs());
    }

    if let Some(true) = config.property::<bool>(("signature", id, "set-body-length"))? {
        signer = signer.body_length(true);
        sealer = sealer.body_length(true);
    }

    if let Some(true) = config.property::<bool>(("signature", id, "report"))? {
        signer = signer.reporting(true);
    }

    if let Some(auid) = config.property::<String>(("signature", id, "auid"))? {
        signer = signer.agent_user_identifier(auid);
    }

    if let Some(atps) = config.property::<String>(("signature", id, "third-party"))? {
        signer = signer.atps(atps);
    }

    if let Some(atpsh) = config.property::<HashAlgorithm>(("signature", id, "third-party-algo"))? {
        signer = signer.atpsh(atpsh);
    }

    Ok((signer, sealer))
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
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
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

impl ParseValue for DkimCanonicalization {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if let Some((headers, body)) = value.split_once('/') {
            Ok(DkimCanonicalization {
                headers: Canonicalization::parse_value(key.clone(), headers.trim())?,
                body: Canonicalization::parse_value(key, body.trim())?,
            })
        } else {
            let c = Canonicalization::parse_value(key, value)?;
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
