/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::borrow::Cow;

use proxy_header::io::ProxiedStream;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

use super::SessionStream;

impl SessionStream for TcpStream {
    fn is_tls(&self) -> bool {
        false
    }

    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
        (Cow::Borrowed(""), Cow::Borrowed(""))
    }
}

impl<T: SessionStream> SessionStream for TlsStream<T> {
    fn is_tls(&self) -> bool {
        true
    }

    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
        let (_, conn) = self.get_ref();

        (
            match conn
                .protocol_version()
                .unwrap_or(rustls::ProtocolVersion::Unknown(0))
            {
                rustls::ProtocolVersion::SSLv2 => "SSLv2",
                rustls::ProtocolVersion::SSLv3 => "SSLv3",
                rustls::ProtocolVersion::TLSv1_0 => "TLSv1.0",
                rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1",
                rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
                rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
                rustls::ProtocolVersion::DTLSv1_0 => "DTLSv1.0",
                rustls::ProtocolVersion::DTLSv1_2 => "DTLSv1.2",
                rustls::ProtocolVersion::DTLSv1_3 => "DTLSv1.3",
                _ => "unknown",
            }
            .into(),
            match conn.negotiated_cipher_suite() {
                Some(rustls::SupportedCipherSuite::Tls13(cs)) => {
                    cs.common.suite.as_str().unwrap_or("unknown")
                }
                Some(rustls::SupportedCipherSuite::Tls12(cs)) => {
                    cs.common.suite.as_str().unwrap_or("unknown")
                }
                None => "unknown",
            }
            .into(),
        )
    }
}

impl SessionStream for ProxiedStream<TcpStream> {
    fn is_tls(&self) -> bool {
        self.proxy_header()
            .ssl()
            .map_or(false, |ssl| ssl.client_ssl())
    }

    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
        self.proxy_header()
            .ssl()
            .map(|ssl| {
                (
                    ssl.version().unwrap_or("unknown").to_string().into(),
                    ssl.cipher().unwrap_or("unknown").to_string().into(),
                )
            })
            .unwrap_or((Cow::Borrowed("unknown"), Cow::Borrowed("unknown")))
    }
}

#[derive(Default)]
pub struct NullIo {
    pub tx_buf: Vec<u8>,
}

impl AsyncWrite for NullIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.tx_buf.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncRead for NullIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unreachable!()
    }
}

impl SessionStream for NullIo {
    fn is_tls(&self) -> bool {
        true
    }

    fn tls_version_and_cipher(
        &self,
    ) -> (
        std::borrow::Cow<'static, str>,
        std::borrow::Cow<'static, str>,
    ) {
        (
            std::borrow::Cow::Borrowed(""),
            std::borrow::Cow::Borrowed(""),
        )
    }
}
