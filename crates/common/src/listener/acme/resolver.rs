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

use crate::{listener::tls::AcmeAuthKey, Core};

use super::{directory::ACME_TLS_ALPN_NAME, AcmeProvider, AcmeResolver};

impl Core {
    pub(crate) fn set_cert(&self, provider: &AcmeProvider, cert: Arc<CertifiedKey>) {
        // Add certificates
        let mut certificates = self.tls.certificates.load().as_ref().clone();
        for domain in provider.domains.iter() {
            certificates.insert(
                domain
                    .strip_prefix("*.")
                    .unwrap_or(domain.as_str())
                    .to_string(),
                cert.clone(),
            );
        }
        self.tls.certificates.store(certificates.into());

        // Remove auth keys
        let mut auth_keys = self.tls.acme_auth_keys.lock();
        auth_keys.retain(|_, v| v.provider_id != provider.id);
        self.tls
            .acme_in_progress
            .store(!auth_keys.is_empty(), Ordering::Relaxed);
    }
    pub(crate) fn set_auth_key(
        &self,
        provider: &AcmeProvider,
        domain: String,
        cert: Arc<CertifiedKey>,
    ) {
        self.tls
            .acme_auth_keys
            .lock()
            .insert(domain, AcmeAuthKey::new(provider.id.clone(), cert));
    }
}

impl ResolvesServerCert for AcmeResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let core = self.core.load();
        if core.has_acme_order_in_progress() && client_hello.is_tls_alpn_challenge() {
            match client_hello.server_name() {
                Some(domain) => {
                    tracing::trace!(
                        context = "acme",
                        event = "auth-key",
                        domain = %domain,
                        "Found client supplied SNI");

                    core.tls
                        .acme_auth_keys
                        .lock()
                        .get(domain)
                        .map(|ak| ak.key.clone())
                }
                None => {
                    tracing::debug!(
                        context = "acme",
                        event = "error",
                        reason = "missing-sni",
                        "client did not supply SNI"
                    );
                    None
                }
            }
        } else {
            core.resolve_certificate(client_hello.server_name())
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
