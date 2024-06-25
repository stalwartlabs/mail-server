/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
