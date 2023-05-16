/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::{io::BufReader, sync::Arc};

use mail_send::Credentials;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::TlsAcceptor;

use ::smtp::lookup::{Item, LookupResult};

pub mod imap;
pub mod smtp;
pub mod sql;

const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgIUCgHGQYUqtelbHGVSzCVwBL3fyEUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIyMDUxNjExNDAzNFoXDTIzMDUx
NjExNDAzNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEAtwS0Fzl3SjaCuKEXgZ/fdWbDoj/qDphyNCAKNevQ0+D0
STNkWCO04aFSH0zcL8zoD9gokNos0i7OU9//ZhZQmex4V6EFdZn8bFwUWN/scUvW
HEFXVjtHldO2isZgIxH9LuwRv7KAgkISuWahqerOVDhe7SeQUV0AJGNEh3cT9PZr
gSY931BxB7n+5k8eoSk8Z1gtBzQzL62kVGpHDKfw8yX8m65owF9eLUBrNzgxmXfC
xpuHwj7hmVhS09PPKeN/RsFS8PsYO7bo0u8jEKalteumjRT7RyUEbioqfo6ZFOGj
FHPIq/uKXS9zN1fpoyNh3ur5hMznQhrqlwBM9KlM7GdBJ0pZ3ad0YjT8IL/GnGKR
85J2WZdLqaQdUZo7nV67FhqdDlNE4MdwiykTMjfmLRXGAVhAzJHKyRKNwmkI2aqe
S7aqeNgvuDBwY80Q9a2rb5py1Aw+L8yCkUBuHboToDpxSVRDNN8DrWNmmsXnxsOG
wRDODy4GICKyxlP+RFSM8xWSQ6y9ktS2OfDBm+Eqcw+3pZKhdz2wgxLkUBJ8X1eh
kJrCA/6LTuhy6m6mMjAfoSOFU7fu88jxaWPgvP7GKyH+LM/t9eucobz2ks5rtSjz
V4Dc5DCS94/OpVRHwHdaFSPbJKBN9Ev8gnNrAyx/aBPGoHBPG/QUiU7dcUNIPt0C
AwEAAaNTMFEwHQYDVR0OBBYEFI167IxBmErB11EqiPPqFLa31ZaMMB8GA1UdIwQY
MBaAFI167IxBmErB11EqiPPqFLa31ZaMMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggIBALU00IOiH5ubEauVCmakms5ermNTZfculnhnDfWTLMeh2+a7
G4cqADErfMhm/mmLbrw33t9s6tCAhQltvewKR40ST9uMPSyiQbYaCXd5DXnuI6Ox
JtNW+UOWIaMf8abnkdLvREOvb8dVQS1i3xq14tAjY5XgpGwCPP8m54b7N3Q7soLn
e5PDhPNTnhRIn2RLuYoZmQmMA5fcqEUDYff4epUww7PhrM1QckZligI3566NlGOf
j1G9JrivBtY0eaJtamIFnGMBT0ThDudxVja2Nv0C2Elry0p4T/o4nc4M67BJ/y1R
vjNLAgFhbxssemU3lZqSd+pykpJBwDBjFSPrZZmQcbk7H6Uz8V1xr/xuzfw6fA13
NWZ5vLgP/DQ13sM+XFlxThKfbPMPVe/UCTvfGtNW+3XyBgPntEkR+fNEawQmzbYl
R+X1ymT9MZnEZqRMf7/UD/SYek1aUJefoew3upjMgxYVvh4F8dqJ+39F+xoFzIA2
1dDAEMzXtjA3zKhZ2cycZbEzpJvYA3eGLuR16Suqfi4kPvfwK0mOhCxQmpayt7/X
vuEzW6dPCH8Hgbb0WvsSppGOvhdbDaZFNfFc5eNSxhyKzu3H3ACNImZRtZE+yixx
0fR8+xz9kDLf8xupV+X9heyFGHSyYU2Lveaevtr2Ij3weLRgJ6LbNALoeKXk
-----END CERTIFICATE-----
";
const PK: &str = "-----BEGIN PRIVATE KEY-----
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
XzVV5pwOxkIDBWDIqMUfwJDChBKfpw==
-----END PRIVATE KEY-----
";

pub fn dummy_tls_acceptor() -> Arc<TlsAcceptor> {
    // Init server config builder with safe defaults
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    // load TLS key/cert files
    let cert_file = &mut BufReader::new(CERT.as_bytes());
    let key_file = &mut BufReader::new(PK.as_bytes());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    // exit if no keys could be parsed
    if keys.is_empty() {
        panic!("Could not locate PKCS 8 private keys.");
    }

    Arc::new(TlsAcceptor::from(Arc::new(
        config.with_single_cert(cert_chain, keys.remove(0)).unwrap(),
    )))
}

pub trait TestItem {
    fn append(&self, append: usize) -> Self;
}

impl TestItem for Item {
    fn append(&self, append: usize) -> Self {
        match self {
            Item::IsAccount(str) => Item::IsAccount(format!("{append}{str}")),
            Item::Authenticate(str) => Item::Authenticate(match str {
                Credentials::Plain { username, secret } => Credentials::Plain {
                    username: username.to_string(),
                    secret: format!("{append}{secret}"),
                },
                Credentials::OAuthBearer { token } => Credentials::OAuthBearer {
                    token: format!("{append}{token}"),
                },
                Credentials::XOauth2 { username, secret } => Credentials::XOauth2 {
                    username: username.to_string(),
                    secret: format!("{append}{secret}"),
                },
            }),
            Item::Verify(str) => Item::Verify(format!("{append}{str}")),
            Item::Expand(str) => Item::Expand(format!("{append}{str}")),
        }
    }
}

pub trait TestLookupResult {
    fn append(&self, append: usize) -> Self;
}

impl TestLookupResult for LookupResult {
    fn append(&self, append: usize) -> Self {
        match self {
            LookupResult::True => LookupResult::True,
            LookupResult::False => LookupResult::False,
            LookupResult::Values(v) => {
                let mut r = Vec::with_capacity(v.len());
                for (pos, val) in v.iter().enumerate() {
                    r.push(if pos == 0 {
                        format!("{append}{val}")
                    } else {
                        val.to_string()
                    });
                }
                LookupResult::Values(r)
            }
        }
    }
}
