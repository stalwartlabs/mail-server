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

use std::sync::{atomic::Ordering, Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use super::{directory::ACME_TLS_ALPN_NAME, AcmeManager};

impl AcmeManager {
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>) {
        self.cert.store(cert);
        self.order_in_progress.store(false, Ordering::Relaxed);
        self.auth_keys.lock().clear();
    }
    pub(crate) fn set_auth_key(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.auth_keys.lock().insert(domain, cert);
    }
}

impl ResolvesServerCert for AcmeManager {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if self.has_order_in_progress() && client_hello.is_tls_alpn_challenge() {
            match client_hello.server_name() {
                None => {
                    tracing::debug!(
                        context = "acme",
                        event = "error",
                        reason = "missing-sni",
                        "client did not supply SNI"
                    );
                    None
                }
                Some(domain) => {
                    tracing::trace!(
                        context = "acme",
                        event = "auth-key",
                        domain = %domain,
                        "Found client supplied SNI");

                    self.auth_keys.lock().get(domain).cloned()
                }
            }
        } else {
            self.cert.load().clone().into()
        }
    }
}

pub trait IsTlsAlpnChallenge {
    fn is_tls_alpn_challenge(&self) -> bool;
}

impl IsTlsAlpnChallenge for ClientHello<'_> {
    fn is_tls_alpn_challenge(&self) -> bool {
        self.alpn().into_iter().flatten().eq([ACME_TLS_ALPN_NAME])
    }
}
