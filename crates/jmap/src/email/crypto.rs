/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, collections::BTreeSet, fmt::Display, io::Cursor, sync::Arc};

use crate::{
    api::{http::ToHttpResponse, management::ManagementApiError, HttpResponse, JsonResponse},
    auth::AccessToken,
    JMAP,
};
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use jmap_proto::{
    error::request::RequestError,
    types::{collection::Collection, property::Property},
};
use mail_builder::{encoders::base64::base64_encode_mime, mime::make_boundary};
use mail_parser::{decoders::base64::base64_decode, Message, MessageParser, MimeHeaders};
use openpgp::{
    parse::Parse,
    serialize::stream,
    types::{KeyFlags, SymmetricAlgorithm},
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rasn::types::{ObjectIdentifier, OctetString};
use rasn_cms::{
    algorithms::{AES128_CBC, AES256_CBC, RSA},
    pkcs7_compat::EncapsulatedContentInfo,
    AlgorithmIdentifier, EncryptedContent, EncryptedContentInfo, EncryptedKey, EnvelopedData,
    IssuerAndSerialNumber, KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo, CONTENT_DATA,
    CONTENT_ENVELOPED_DATA,
};
use rsa::{pkcs1::DecodeRsaPublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use sequoia_openpgp as openpgp;
use serde_json::json;
use store::{
    write::{BatchBuilder, Bincode, ToBitmaps, F_CLEAR, F_VALUE},
    Deserialize, Serialize,
};

const P: openpgp::policy::StandardPolicy<'static> = openpgp::policy::StandardPolicy::new();

#[derive(Debug)]
pub enum EncryptMessageError {
    AlreadyEncrypted,
    Error(String),
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum Algorithm {
    Aes128,
    Aes256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EncryptionMethod {
    PGP,
    SMIME,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptionParams {
    pub method: EncryptionMethod,
    pub algo: Algorithm,
    pub certs: Vec<Vec<u8>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
#[serde(tag = "type")]
pub enum EncryptionType {
    PGP {
        algo: Algorithm,
        certs: String,
    },
    SMIME {
        algo: Algorithm,
        certs: String,
    },
    #[default]
    Disabled,
}

#[allow(async_fn_in_trait)]
pub trait EncryptMessage {
    async fn encrypt(&self, params: &EncryptionParams) -> Result<Vec<u8>, EncryptMessageError>;
    fn is_encrypted(&self) -> bool;
}

impl EncryptMessage for Message<'_> {
    async fn encrypt(&self, params: &EncryptionParams) -> Result<Vec<u8>, EncryptMessageError> {
        let root = self.root_part();
        let raw_message = self.raw_message();
        let mut outer_message = Vec::with_capacity((raw_message.len() as f64 * 1.5) as usize);
        let mut inner_message = Vec::with_capacity(raw_message.len());

        // Move MIME headers and body to inner message
        for header in root.headers() {
            (if header.name.is_mime_header() {
                &mut inner_message
            } else {
                &mut outer_message
            })
            .extend_from_slice(&raw_message[header.offset_field()..header.offset_end()]);
        }
        inner_message.extend_from_slice(b"\r\n");
        inner_message.extend_from_slice(&raw_message[root.raw_body_offset()..]);

        // Encrypt inner message
        match params.method {
            EncryptionMethod::PGP => {
                // Prepare encrypted message
                let boundary = make_boundary("_");
                outer_message.extend_from_slice(
                    concat!(
                        "Content-Type: multipart/encrypted;\r\n\t",
                        "protocol=\"application/pgp-encrypted\";\r\n\t",
                        "boundary=\""
                    )
                    .as_bytes(),
                );
                outer_message.extend_from_slice(boundary.as_bytes());
                outer_message.extend_from_slice(
                    concat!(
                        "\"\r\n\r\n",
                        "OpenPGP/MIME message (Automatically encrypted by Stalwart)\r\n\r\n",
                        "--"
                    )
                    .as_bytes(),
                );
                outer_message.extend_from_slice(boundary.as_bytes());
                outer_message.extend_from_slice(
                    concat!(
                        "\r\nContent-Type: application/pgp-encrypted\r\n\r\n",
                        "Version: 1\r\n\r\n--"
                    )
                    .as_bytes(),
                );
                outer_message.extend_from_slice(boundary.as_bytes());
                outer_message.extend_from_slice(
                    concat!(
                        "\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n",
                        "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n"
                    )
                    .as_bytes(),
                );

                let certs = params
                    .certs
                    .iter()
                    .map(openpgp::Cert::from_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|err| {
                        EncryptMessageError::Error(format!(
                            "Failed to parse OpenPGP public key: {}",
                            err
                        ))
                    })?;

                // Encrypt contents (TODO: use rayon)
                let algo = params.algo;
                let encrypted_contents = tokio::task::spawn_blocking(move || {
                    // Parse public key
                    let mut keys = Vec::with_capacity(certs.len());
                    let policy = openpgp::policy::StandardPolicy::new();

                    for cert in &certs {
                        for key in cert
                            .keys()
                            .with_policy(&policy, None)
                            .supported()
                            .alive()
                            .revoked(false)
                            .key_flags(&KeyFlags::empty().set_transport_encryption())
                        {
                            keys.push(key);
                        }
                    }

                    // Compose a writer stack corresponding to the output format and
                    // packet structure we want.
                    let mut sink = Vec::with_capacity(inner_message.len());

                    // Stream an OpenPGP message.
                    let message = stream::Armorer::new(stream::Message::new(&mut sink))
                        .build()
                        .map_err(|err| {
                            EncryptMessageError::Error(format!("Failed to create armorer: {}", err))
                        })?;
                    let message = stream::Encryptor2::for_recipients(message, keys)
                        .symmetric_algo(match algo {
                            Algorithm::Aes128 => SymmetricAlgorithm::AES128,
                            Algorithm::Aes256 => SymmetricAlgorithm::AES256,
                        })
                        .build()
                        .map_err(|err| {
                            EncryptMessageError::Error(format!(
                                "Failed to build encryptor: {}",
                                err
                            ))
                        })?;
                    let mut message =
                        stream::LiteralWriter::new(message).build().map_err(|err| {
                            EncryptMessageError::Error(format!(
                                "Failed to create literal writer: {}",
                                err
                            ))
                        })?;
                    std::io::copy(&mut Cursor::new(inner_message), &mut message).map_err(
                        |err| {
                            EncryptMessageError::Error(format!(
                                "Failed to encrypt message: {}",
                                err
                            ))
                        },
                    )?;
                    message.finalize().map_err(|err| {
                        EncryptMessageError::Error(format!("Failed to finalize message: {}", err))
                    })?;

                    String::from_utf8(sink).map_err(|err| {
                        EncryptMessageError::Error(format!(
                            "Failed to convert encrypted message to UTF-8: {}",
                            err
                        ))
                    })
                })
                .await
                .map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to encrypt message: {}", err))
                })??;
                outer_message.extend_from_slice(encrypted_contents.as_bytes());
                outer_message.extend_from_slice(b"\r\n--");
                outer_message.extend_from_slice(boundary.as_bytes());
                outer_message.extend_from_slice(b"--\r\n");
            }
            EncryptionMethod::SMIME => {
                // Generate random IV
                let mut rng = StdRng::from_entropy();
                let mut iv = vec![0u8; 16];
                rng.fill_bytes(&mut iv);

                // Generate random key
                let mut key = vec![0u8; params.algo.key_size()];
                rng.fill_bytes(&mut key);

                // Encrypt contents (TODO: use rayon)
                let algo = params.algo;
                let (encrypted_contents, key, iv) = tokio::task::spawn_blocking(move || {
                    (algo.encrypt(&key, &iv, &inner_message), key, iv)
                })
                .await
                .map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to encrypt message: {}", err))
                })?;

                // Encrypt key using public keys
                #[allow(clippy::mutable_key_type)]
                let mut recipient_infos = BTreeSet::new();
                for cert in &params.certs {
                    let cert =
                        rasn::der::decode::<rasn_pkix::Certificate>(cert).map_err(|err| {
                            EncryptMessageError::Error(format!(
                                "Failed to parse certificate: {}",
                                err
                            ))
                        })?;

                    let public_key = RsaPublicKey::from_pkcs1_der(
                        cert.tbs_certificate
                            .subject_public_key_info
                            .subject_public_key
                            .as_raw_slice(),
                    )
                    .map_err(|err| {
                        EncryptMessageError::Error(format!("Failed to parse public key: {}", err))
                    })?;
                    let encrypted_key = public_key
                        .encrypt(&mut rng, Pkcs1v15Encrypt, &key[..])
                        .map_err(|err| {
                            EncryptMessageError::Error(format!("Failed to encrypt key: {}", err))
                        })
                        .unwrap();

                    recipient_infos.insert(RecipientInfo::KeyTransRecipientInfo(
                        KeyTransRecipientInfo {
                            version: 0.into(),
                            rid: RecipientIdentifier::IssuerAndSerialNumber(
                                IssuerAndSerialNumber {
                                    issuer: cert.tbs_certificate.issuer,
                                    serial_number: cert.tbs_certificate.serial_number,
                                },
                            ),
                            key_encryption_algorithm: AlgorithmIdentifier {
                                algorithm: RSA.into(),
                                parameters: Some(
                                    rasn::der::encode(&())
                                        .map_err(|err| {
                                            EncryptMessageError::Error(format!(
                                                "Failed to encode RSA algorithm identifier: {}",
                                                err
                                            ))
                                        })?
                                        .into(),
                                ),
                            },
                            encrypted_key: EncryptedKey::from(encrypted_key),
                        },
                    ));
                }

                let pkcs7 = rasn::der::encode(&EncapsulatedContentInfo {
                    content_type: CONTENT_ENVELOPED_DATA.into(),
                    content: Some(
                        rasn::der::encode(&EnvelopedData {
                            version: 0.into(),
                            originator_info: None,
                            recipient_infos,
                            encrypted_content_info: EncryptedContentInfo {
                                content_type: CONTENT_DATA.into(),
                                content_encryption_algorithm: AlgorithmIdentifier {
                                    algorithm: params.algo.to_algorithm_identifier(),
                                    parameters: Some(
                                        rasn::der::encode(&OctetString::from(iv))
                                            .map_err(|err| {
                                                EncryptMessageError::Error(format!(
                                                    "Failed to encode IV: {}",
                                                    err
                                                ))
                                            })?
                                            .into(),
                                    ),
                                },
                                encrypted_content: Some(EncryptedContent::from(encrypted_contents)),
                            },
                            unprotected_attrs: None,
                        })
                        .map_err(|err| {
                            EncryptMessageError::Error(format!(
                                "Failed to encode EnvelopedData: {}",
                                err
                            ))
                        })?
                        .into(),
                    ),
                })
                .map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to encode ContentInfo: {}", err))
                })?;

                // Generate message
                outer_message.extend_from_slice(
                    concat!(
                        "Content-Type: application/pkcs7-mime;\r\n",
                        "\tname=\"smime.p7m\";\r\n",
                        "\tsmime-type=enveloped-data\r\n",
                        "Content-Disposition: attachment;\r\n",
                        "\tfilename=\"smime.p7m\"\r\n",
                        "Content-Transfer-Encoding: base64\r\n\r\n"
                    )
                    .as_bytes(),
                );
                base64_encode_mime(&pkcs7, &mut outer_message, false).map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to base64 encode PKCS7: {}", err))
                })?;
            }
        }

        Ok(outer_message)
    }

    fn is_encrypted(&self) -> bool {
        self.content_type().map_or(false, |ct| {
            let main_type = ct.c_type.as_ref();
            let sub_type = ct
                .c_subtype
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or_default();

            (main_type.eq_ignore_ascii_case("application")
                && (sub_type.eq_ignore_ascii_case("pkcs7-mime")
                    || sub_type.eq_ignore_ascii_case("pkcs7-signature")
                    || (sub_type.eq_ignore_ascii_case("octet-stream")
                        && self.attachment_name().map_or(false, |name| {
                            name.rsplit_once('.').map_or(false, |(_, ext)| {
                                ["p7m", "p7s", "p7c", "p7z"].contains(&ext)
                            })
                        }))))
                || (main_type.eq_ignore_ascii_case("multipart")
                    && sub_type.eq_ignore_ascii_case("encrypted"))
        })
    }
}

impl Algorithm {
    fn key_size(&self) -> usize {
        match self {
            Algorithm::Aes128 => 16,
            Algorithm::Aes256 => 32,
        }
    }

    fn to_algorithm_identifier(self) -> ObjectIdentifier {
        match self {
            Algorithm::Aes128 => AES128_CBC.into(),
            Algorithm::Aes256 => AES256_CBC.into(),
        }
    }

    fn encrypt(&self, key: &[u8], iv: &[u8], contents: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::Aes128 => cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(contents),
            Algorithm::Aes256 => cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(contents),
        }
    }
}

pub fn try_parse_certs(
    expected_method: EncryptionMethod,
    cert: Vec<u8>,
) -> Result<Vec<Vec<u8>>, Cow<'static, str>> {
    // Check if it's a PEM file
    let (method, certs) = if let Some(result) = try_parse_pem(&cert)? {
        result
    } else if rasn::der::decode::<rasn_pkix::Certificate>(&cert[..]).is_ok() {
        (EncryptionMethod::SMIME, vec![cert])
    } else if let Ok(cert_) = openpgp::Cert::from_bytes(&cert[..]) {
        if !has_pgp_keys(cert_) {
            (EncryptionMethod::PGP, vec![cert])
        } else {
            return Err("Could not find any suitable keys in certificate".into());
        }
    } else {
        return Err("Could not find any valid certificates".into());
    };

    if method == expected_method {
        Ok(certs)
    } else {
        Err("No valid certificates found for the selected encryption".into())
    }
}

fn has_pgp_keys(cert: openpgp::Cert) -> bool {
    cert.keys()
        .with_policy(&P, None)
        .supported()
        .alive()
        .revoked(false)
        .key_flags(&KeyFlags::empty().set_transport_encryption())
        .next()
        .is_some()
}

#[allow(clippy::type_complexity)]
fn try_parse_pem(
    bytes_: &[u8],
) -> Result<Option<(EncryptionMethod, Vec<Vec<u8>>)>, Cow<'static, str>> {
    if let Some(internal) = std::str::from_utf8(bytes_)
        .ok()
        .and_then(|cert| cert.strip_prefix("-----STALWART CERTIFICATE-----"))
    {
        return base64_decode(internal.as_bytes())
            .ok_or(Cow::from("Failed to decode base64"))
            .and_then(|bytes| {
                Bincode::<EncryptionParams>::deserialize(&bytes)
                    .map_err(|_| Cow::from("Failed to deserialize internal certificate"))
            })
            .map(|params| Some((params.inner.method, params.inner.certs)));
    }

    let mut bytes = bytes_.iter().enumerate();
    let mut buf = vec![];
    let mut method = None;
    let mut certs = vec![];

    loop {
        // Find start of PEM block
        let mut start_pos = 0;
        for (pos, &ch) in bytes.by_ref() {
            if ch.is_ascii_whitespace() {
                continue;
            } else if ch == b'-' {
                start_pos = pos;
                break;
            } else {
                return Ok(None);
            }
        }

        // Find block type
        for (_, &ch) in bytes.by_ref() {
            match ch {
                b'-' => (),
                b'\n' => break,
                _ => {
                    if ch.is_ascii() {
                        buf.push(ch.to_ascii_uppercase());
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
        if buf.is_empty() {
            break;
        }

        // Find type
        let tag = std::str::from_utf8(&buf).unwrap();
        if tag.contains("CERTIFICATE") {
            if method.map_or(false, |m| m == EncryptionMethod::PGP) {
                return Err("Cannot mix OpenPGP and S/MIME certificates".into());
            } else {
                method = Some(EncryptionMethod::SMIME);
            }
        } else if tag.contains("PGP") {
            if method.map_or(false, |m| m == EncryptionMethod::SMIME) {
                return Err("Cannot mix OpenPGP and S/MIME certificates".into());
            } else {
                method = Some(EncryptionMethod::PGP);
            }
        } else {
            // Ignore block
            let mut found_end = false;
            for (_, &ch) in bytes.by_ref() {
                if ch == b'-' {
                    found_end = true;
                } else if ch == b'\n' && found_end {
                    break;
                }
            }
            buf.clear();
            continue;
        }

        // Collect base64
        buf.clear();
        let mut found_end = false;
        let mut end_pos = 0;
        for (pos, &ch) in bytes.by_ref() {
            match ch {
                b'-' => {
                    found_end = true;
                }
                b'\n' => {
                    if found_end {
                        end_pos = pos;
                        break;
                    }
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        buf.push(ch);
                    }
                }
            }
        }

        // Decode base64
        let cert =
            base64_decode(&buf).ok_or_else(|| Cow::from("Failed to decode base64 certificate."))?;
        match method.unwrap() {
            EncryptionMethod::PGP => match openpgp::Cert::from_bytes(bytes_) {
                Ok(cert) => {
                    if !has_pgp_keys(cert) {
                        return Err("Could not find any suitable keys in OpenPGP public key".into());
                    }
                    certs.push(
                        bytes_
                            .get(start_pos..end_pos + 1)
                            .unwrap_or_default()
                            .to_vec(),
                    );
                }
                Err(err) => {
                    return Err(format!("Failed to decode OpenPGP public key: {err}").into())
                }
            },
            EncryptionMethod::SMIME => {
                if let Err(err) = rasn::der::decode::<rasn_pkix::Certificate>(&cert) {
                    return Err(format!("Failed to decode X509 certificate: {err}").into());
                }
                certs.push(cert);
            }
        }
        buf.clear();
    }

    Ok(method.map(|method| (method, certs)))
}

impl Serialize for &EncryptionParams {
    fn serialize(self) -> Vec<u8> {
        let len = bincode::serialized_size(&self).unwrap_or_default();
        let mut buf = Vec::with_capacity(len as usize + 1);
        buf.push(1);
        let _ = bincode::serialize_into(&mut buf, &self);
        buf
    }
}

impl Deserialize for EncryptionParams {
    fn deserialize(bytes: &[u8]) -> store::Result<Self> {
        let version = *bytes.first().ok_or_else(|| {
            store::Error::InternalError(
                "Failed to read version while deserializing encryption params".to_string(),
            )
        })?;
        match version {
            1 if bytes.len() > 1 => bincode::deserialize(&bytes[1..]).map_err(|err| {
                store::Error::InternalError(format!(
                    "Failed to deserialize encryption params: {}",
                    err
                ))
            }),

            _ => Err(store::Error::InternalError(format!(
                "Unknown encryption params version: {}",
                version
            ))),
        }
    }
}

impl ToBitmaps for &EncryptionParams {
    fn to_bitmaps(&self, _: &mut Vec<store::write::Operation>, _: u8, _: bool) {
        unreachable!()
    }
}

impl JMAP {
    pub async fn handle_crypto_get(&self, access_token: Arc<AccessToken>) -> HttpResponse {
        match self
            .get_property::<EncryptionParams>(
                access_token.primary_id(),
                Collection::Principal,
                0,
                Property::Parameters,
            )
            .await
        {
            Ok(params) => {
                let ec = params
                    .map(|params| {
                        let method = params.method;
                        let algo = params.algo;
                        let mut certs = Vec::new();
                        certs.extend_from_slice(b"-----STALWART CERTIFICATE-----\r\n");
                        let _ = base64_encode_mime(
                            &Bincode::new(params).serialize(),
                            &mut certs,
                            false,
                        );
                        certs.extend_from_slice(b"\r\n");
                        let certs = String::from_utf8(certs).unwrap_or_default();

                        match method {
                            EncryptionMethod::PGP => EncryptionType::PGP { algo, certs },
                            EncryptionMethod::SMIME => EncryptionType::SMIME { algo, certs },
                        }
                    })
                    .unwrap_or(EncryptionType::Disabled);

                JsonResponse::new(json!({
                    "data": ec,
                }))
                .into_http_response()
            }
            Err(err) => {
                tracing::warn!(
                    context = "store",
                    event = "error",
                    reason = ?err,
                    "Database error while fetching encryption parameters"
                );

                RequestError::internal_server_error().into_http_response()
            }
        }
    }

    pub async fn handle_crypto_post(
        &self,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        let request =
            match serde_json::from_slice::<EncryptionType>(body.as_deref().unwrap_or_default()) {
                Ok(request) => request,
                Err(err) => return err.into_http_response(),
            };

        let (method, algo, certs) = match request {
            EncryptionType::PGP { algo, certs } => (EncryptionMethod::PGP, algo, certs),
            EncryptionType::SMIME { algo, certs } => (EncryptionMethod::SMIME, algo, certs),
            EncryptionType::Disabled => {
                // Disable encryption at rest
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(access_token.primary_id())
                    .with_collection(Collection::Principal)
                    .update_document(0)
                    .value(Property::Parameters, (), F_VALUE | F_CLEAR);
                return match self.core.storage.data.write(batch.build()).await {
                    Ok(_) => JsonResponse::new(json!({
                        "data": (),
                    }))
                    .into_http_response(),
                    Err(err) => err.into_http_response(),
                };
            }
        };

        // Make sure Encryption is enabled
        if !self.core.jmap.encrypt {
            return ManagementApiError::Unsupported {
                details: "Encryption-at-rest has been disabled by the system administrator".into(),
            }
            .into_http_response();
        }

        // Parse certificates
        let params = match try_parse_certs(method, certs.into_bytes()) {
            Ok(certs) => EncryptionParams {
                method,
                algo,
                certs,
            },
            Err(err) => return ManagementApiError::from(err).into_http_response(),
        };

        // Try a test encryption
        if let Err(EncryptMessageError::Error(message)) = MessageParser::new()
            .parse("Subject: test\r\ntest\r\n".as_bytes())
            .unwrap()
            .encrypt(&params)
            .await
        {
            return ManagementApiError::from(message).into_http_response();
        }

        // Save encryption params
        let num_certs = params.certs.len();
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(access_token.primary_id())
            .with_collection(Collection::Principal)
            .update_document(0)
            .value(Property::Parameters, &params, F_VALUE);
        match self.core.storage.data.write(batch.build()).await {
            Ok(_) => JsonResponse::new(json!({
                "data": num_certs,
            }))
            .into_http_response(),
            Err(err) => err.into_http_response(),
        }
    }
}

impl Display for EncryptionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionMethod::PGP => write!(f, "OpenPGP"),
            EncryptionMethod::SMIME => write!(f, "S/MIME"),
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Aes128 => write!(f, "AES-128"),
            Algorithm::Aes256 => write!(f, "AES-256"),
        }
    }
}
