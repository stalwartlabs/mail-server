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

use std::{borrow::Cow, net::IpAddr};

use super::{Macro, Macros};

pub trait IntoMacroValue<'x> {
    fn into_macro_value(self) -> Cow<'x, [u8]>;
}

impl<'x> Macros<'x> {
    pub fn new() -> Self {
        Macros::default()
    }

    pub fn with_cmd_code(mut self, cmd_code: u8) -> Self {
        self.cmdcode = cmd_code;
        self
    }

    pub fn with_macro(mut self, name: &'static [u8], value: impl IntoMacroValue<'x>) -> Self {
        self.macros.push(Macro {
            name,
            value: value.into_macro_value(),
        });
        self
    }

    pub fn with_queue_id(self, queue_id: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"i", queue_id)
    }

    pub fn with_local_hostname(self, my_hostname: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"j", my_hostname)
    }

    pub fn with_validated_client_name(self, client_name: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"_", client_name)
    }

    pub fn with_sasl_login_name(self, sasl_login_name: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{auth_authen}", sasl_login_name)
    }

    pub fn with_sasl_sender(self, sasl_sender: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{auth_author}", sasl_sender)
    }

    pub fn with_sasl_method(self, sasl_method: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{auth_type}", sasl_method)
    }

    pub fn with_client_address(self, client_address: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{client_addr}", client_address)
    }

    pub fn with_client_connections(self, client_connections: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{client_connections}", client_connections)
    }

    pub fn with_client_name(self, client_name: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{client_name}", client_name)
    }

    pub fn with_client_port(self, client_port: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{client_port}", client_port)
    }

    pub fn with_client_ptr(self, client_ptr: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{client_ptr}", client_ptr)
    }

    pub fn with_cert_issuer(self, cert_issuer: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{cert_issuer}", cert_issuer)
    }

    pub fn with_cert_subject(self, cert_subject: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{cert_subject}", cert_subject)
    }

    pub fn with_cipher_bits(self, cipher_bits: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{cipher_bits}", cipher_bits)
    }

    pub fn with_cipher(self, cipher: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{cipher}", cipher)
    }

    pub fn with_daemon_address(self, daemon_address: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{daemon_addr}", daemon_address)
    }

    pub fn with_daemon_name(self, daemon_name: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{daemon_name}", daemon_name)
    }

    pub fn with_daemon_port(self, daemon_port: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{daemon_port}", daemon_port)
    }

    pub fn with_mail_address(self, mail_address: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{mail_addr}", mail_address)
    }

    pub fn with_mail_host(self, mail_host_address: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{mail_host}", mail_host_address)
    }

    pub fn with_mail_mailer(self, mail_mailer: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{mail_mailer}", mail_mailer)
    }

    pub fn with_rcpt_address(self, rcpt_address: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{rcpt_addr}", rcpt_address)
    }

    pub fn with_rcpt_host(self, rcpt_host: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{rcpt_host}", rcpt_host)
    }

    pub fn with_rcpt_mailer(self, rcpt_mailer: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{rcpt_mailer}", rcpt_mailer)
    }

    pub fn with_tls_version(self, tls_version: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{tls_version}", tls_version)
    }

    pub fn with_version(self, version: impl IntoMacroValue<'x>) -> Self {
        self.with_macro(b"{v}", version)
    }
}

impl<'x> IntoMacroValue<'x> for IpAddr {
    fn into_macro_value(self) -> Cow<'x, [u8]> {
        Cow::Owned(self.to_string().into_bytes())
    }
}

impl<'x> IntoMacroValue<'x> for u16 {
    fn into_macro_value(self) -> Cow<'x, [u8]> {
        Cow::Owned(self.to_string().into_bytes())
    }
}

impl<'x> IntoMacroValue<'x> for &'x [u8] {
    fn into_macro_value(self) -> Cow<'x, [u8]> {
        Cow::Borrowed(self)
    }
}

impl<'x> IntoMacroValue<'x> for &'x str {
    fn into_macro_value(self) -> Cow<'x, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl<'x> IntoMacroValue<'x> for String {
    fn into_macro_value(self) -> Cow<'x, [u8]> {
        Cow::Owned(self.into_bytes())
    }
}

impl<'x> IntoMacroValue<'x> for &'x String {
    fn into_macro_value(self) -> Cow<'x, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl<'x> IntoMacroValue<'x> for Vec<u8> {
    fn into_macro_value(self) -> Cow<'x, [u8]> {
        Cow::Owned(self)
    }
}

impl<'x> IntoMacroValue<'x> for &'x Vec<u8> {
    fn into_macro_value(self) -> Cow<'x, [u8]> {
        Cow::Borrowed(self)
    }
}
