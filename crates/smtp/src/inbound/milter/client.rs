/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::session::Milter;
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use trc::MilterEvent;

use super::{
    protocol::{SMFIC_CONNECT, SMFIC_HELO, SMFIC_MAIL, SMFIC_RCPT},
    receiver::{FrameResult, Receiver},
    *,
};

const MILTER_CHUNK_SIZE: usize = 65535;

impl MilterClient<TcpStream> {
    pub async fn connect(config: &Milter, session_id: u64) -> Result<Self> {
        tokio::time::timeout(config.timeout_command, async {
            let mut last_err = Error::Disconnected;
            for addr in &config.addrs {
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        return Ok(MilterClient {
                            stream,
                            timeout_cmd: config.timeout_command,
                            timeout_data: config.timeout_data,
                            buf: vec![0u8; 8192],
                            bytes_read: 0,
                            receiver: Receiver::with_max_frame_len(config.max_frame_len),
                            options: 0,
                            version: config.protocol_version,
                            session_id,
                            flags_actions: config.flags_actions.unwrap_or(
                                SMFIF_ADDHDRS
                                    | SMFIF_CHGBODY
                                    | SMFIF_ADDRCPT
                                    | SMFIF_DELRCPT
                                    | SMFIF_CHGHDRS
                                    | SMFIF_QUARANTINE
                                    | SMFIF_CHGFROM
                                    | SMFIF_ADDRCPT_PAR,
                            ),
                            flags_protocol: config.flags_protocol.unwrap_or(0x42),
                            id: config.id.clone(),
                        });
                    }
                    Err(err) => {
                        last_err = Error::Io(err);
                    }
                }
            }
            Err(last_err)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn into_tls(
        self,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
    ) -> Result<MilterClient<TlsStream<TcpStream>>> {
        tokio::time::timeout(self.timeout_cmd, async {
            Ok(MilterClient {
                stream: tls_connector
                    .connect(
                        ServerName::try_from(tls_hostname)
                            .map_err(|_| Error::TLSInvalidName)?
                            .to_owned(),
                        self.stream,
                    )
                    .await?,
                buf: self.buf,
                timeout_cmd: self.timeout_cmd,
                timeout_data: self.timeout_data,
                receiver: self.receiver,
                bytes_read: self.bytes_read,
                options: self.options,
                version: self.version,
                session_id: self.session_id,
                flags_actions: self.flags_actions,
                flags_protocol: self.flags_protocol,
                id: self.id,
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> MilterClient<T> {
    pub async fn init(&mut self) -> super::Result<Options> {
        self.write(Command::OptionNegotiation(Options {
            version: match self.version {
                MilterVersion::V2 => 2,
                MilterVersion::V6 => 6,
            },
            actions: self.flags_actions,
            protocol: self.flags_protocol,
        }))
        .await?;
        match self.read().await? {
            Response::OptionNegotiation(options) => {
                self.options = options.protocol;
                Ok(options)
            }
            response => Err(Error::Unexpected(response)),
        }
    }

    pub async fn connection(
        &mut self,
        hostname: impl AsRef<[u8]>,
        remote_ip: IpAddr,
        remote_port: u16,
        macros: Macros<'_>,
    ) -> super::Result<Action> {
        if !self.has_option(SMFIP_NOCONNECT) {
            self.write(Command::Macro {
                macros: macros.with_cmd_code(SMFIC_CONNECT),
            })
            .await?;
            self.write(Command::Connect {
                hostname: hostname.as_ref(),
                port: remote_port,
                address: remote_ip,
            })
            .await?;
            if !self.has_option(SMFIP_NR_CONN) {
                return self.read().await?.into_action();
            }
        }

        Ok(Action::Accept)
    }

    pub async fn helo(
        &mut self,
        hostname: impl AsRef<[u8]>,
        macros: Macros<'_>,
    ) -> super::Result<Action> {
        if !self.has_option(SMFIP_NOHELO) {
            self.write(Command::Macro {
                macros: macros.with_cmd_code(SMFIC_HELO),
            })
            .await?;
            self.write(Command::Helo {
                hostname: hostname.as_ref(),
            })
            .await?;
            if !self.has_option(SMFIP_NR_HELO) {
                return self.read().await?.into_action();
            }
        }
        Ok(Action::Accept)
    }

    pub async fn mail_from<A, V>(
        &mut self,
        addr: A,
        params: Option<&[V]>,
        macros: Macros<'_>,
    ) -> super::Result<Action>
    where
        A: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        if !self.has_option(SMFIP_NOMAIL) {
            self.write(Command::Macro {
                macros: macros.with_cmd_code(SMFIC_MAIL),
            })
            .await?;
            self.write(Command::MailFrom {
                sender: addr.as_ref(),
                args: params.map(|params| params.iter().map(|value| value.as_ref()).collect()),
            })
            .await?;
            if !self.has_option(SMFIP_NR_MAIL) {
                return self.read().await?.into_action();
            }
        }
        Ok(Action::Accept)
    }

    pub async fn rcpt_to<A, V>(
        &mut self,
        addr: A,
        params: Option<&[V]>,
        macros: Macros<'_>,
    ) -> super::Result<Action>
    where
        A: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        if !self.has_option(SMFIP_NORCPT) {
            self.write(Command::Macro {
                macros: macros.with_cmd_code(SMFIC_RCPT),
            })
            .await?;
            self.write(Command::Rcpt {
                recipient: addr.as_ref(),
                args: params.map(|params| params.iter().map(|value| value.as_ref()).collect()),
            })
            .await?;
            if !self.has_option(SMFIP_NR_RCPT) {
                return self.read().await?.into_action();
            }
        }
        Ok(Action::Accept)
    }

    pub async fn headers<I, H, V>(&mut self, headers: I) -> super::Result<Action>
    where
        I: Iterator<Item = (H, V)>,
        H: AsRef<str>,
        V: AsRef<str>,
    {
        if !self.has_option(SMFIP_NOHDRS) {
            for (name, value) in headers {
                self.write(Command::Header {
                    name: name.as_ref().trim().as_bytes(),
                    value: value.as_ref().trim().as_bytes(),
                })
                .await?;
                if !self.has_option(SMFIP_NR_HDR) {
                    match self.read().await? {
                        Response::Action(Action::Accept | Action::Continue) => (),
                        Response::Action(action) => return Ok(action),
                        response => return Err(Error::Unexpected(response)),
                    }
                }
            }

            // Write EndOfHeaders
            self.write(Command::EndOfHeader).await?;
            if !self.has_option(SMFIP_NR_EOH) {
                return self.read().await?.into_action();
            }
        }
        Ok(Action::Accept)
    }

    pub async fn data(&mut self) -> super::Result<Action> {
        if matches!(self.version, MilterVersion::V6) && !self.has_option(SMFIP_NODATA) {
            self.write(Command::Data).await?;
            if !self.has_option(SMFIP_NR_DATA) {
                return self.read().await?.into_action();
            }
        }
        Ok(Action::Accept)
    }

    pub async fn body(&mut self, body: &[u8]) -> super::Result<(Action, Vec<Modification>)> {
        if !self.has_option(SMFIP_NOBODY) {
            // Write body chunks
            for value in body.chunks(MILTER_CHUNK_SIZE) {
                self.write(Command::Body { value }).await?;
                if !self.has_option(SMFIP_NR_BODY) {
                    match self.read().await? {
                        Response::Action(Action::Accept | Action::Continue)
                        | Response::Progress => (),
                        Response::Skip => break,
                        Response::Action(reject) => {
                            return Ok((reject, Vec::new()));
                        }
                        response => return Err(Error::Unexpected(response)),
                    }
                }
            }

            // Write EndOfBody
            self.write(Command::EndOfBody).await?;

            // Collect responses
            let mut modifications = Vec::new();
            loop {
                match self.read().await? {
                    Response::Action(action) => {
                        return Ok((action, modifications));
                    }
                    Response::Modification(modification) => {
                        modifications.push(modification);
                    }
                    Response::Progress => (),
                    unexpected => {
                        return Err(Error::Unexpected(unexpected));
                    }
                }
            }
        } else {
            Ok((Action::Accept, vec![]))
        }
    }

    pub async fn abort(&mut self) -> super::Result<()> {
        self.write(Command::Abort).await
    }

    pub async fn quit(&mut self) -> super::Result<()> {
        self.write(Command::Quit).await
    }

    async fn write(&mut self, action: Command<'_>) -> super::Result<()> {
        trc::event!(
            Milter(MilterEvent::Write),
            SessionId = self.session_id,
            Id = self.id.to_string(),
            Contents = action.to_string(),
        );

        tokio::time::timeout(self.timeout_cmd, async {
            self.stream.write_all(action.serialize().as_ref()).await?;
            self.stream.flush().await.map_err(Error::Io)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    async fn read(&mut self) -> super::Result<Response> {
        loop {
            match self.receiver.read_frame(&self.buf[..self.bytes_read]) {
                FrameResult::Frame(frame) => {
                    if let Some(response) = Response::deserialize(&frame) {
                        trc::event!(
                            Milter(MilterEvent::Read),
                            SessionId = self.session_id,
                            Id = self.id.to_string(),
                            Contents = response.to_string(),
                        );

                        return Ok(response);
                    } else {
                        return Err(Error::FrameInvalid(frame.into_owned()));
                    }
                }
                FrameResult::Incomplete => {
                    self.bytes_read = tokio::time::timeout(self.timeout_data, async {
                        self.stream.read(&mut self.buf).await.map_err(Error::Io)
                    })
                    .await
                    .map_err(|_| Error::Timeout)??;
                    if self.bytes_read == 0 {
                        return Err(Error::Disconnected);
                    }
                }
                FrameResult::TooLarge(size) => return Err(Error::FrameTooLarge(size)),
            }
        }
    }

    #[inline(always)]
    fn has_option(&self, opt: u32) -> bool {
        self.options & opt == opt
    }

    pub fn with_version(mut self, version: MilterVersion) -> Self {
        self.version = version;
        self
    }
}
