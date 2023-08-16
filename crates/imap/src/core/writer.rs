/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
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

use std::borrow::Cow;

use tokio::{
    io::{AsyncRead, AsyncWriteExt, WriteHalf},
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_rustls::server::TlsStream;
use tracing::debug;

use super::{Session, SessionData};

const IPC_CHANNEL_BUFFER: usize = 128;

pub enum Event {
    Stream(WriteHalf<TcpStream>),
    StreamTls(WriteHalf<TlsStream<TcpStream>>),
    Bytes(Cow<'static, [u8]>),
    Upgrade(oneshot::Sender<WriteHalf<TcpStream>>),
}

pub fn spawn_writer(mut stream: Event, span: tracing::Span) -> mpsc::Sender<Event> {
    let (tx, mut rx) = mpsc::channel::<Event>(IPC_CHANNEL_BUFFER);
    tokio::spawn(async move {
        'outer: loop {
            match stream {
                Event::Stream(mut stream_tx) => {
                    while let Some(event) = rx.recv().await {
                        match event {
                            Event::Bytes(bytes) => {
                                tracing::trace!(
                                    parent: &span,
                                    event = "write",
                                    data = std::str::from_utf8(bytes.as_ref()).unwrap_or_default(),
                                    size = bytes.len()
                                );
                                /*let c = println!(
                                    "<- {:?}",
                                    String::from_utf8_lossy(
                                        &bytes[..std::cmp::min(bytes.len(), 100)]
                                    )
                                );*/

                                match stream_tx.write_all(bytes.as_ref()).await {
                                    Ok(_) => {
                                        let _ = stream_tx.flush().await;
                                    }
                                    Err(err) => {
                                        debug!("Failed to write to stream: {}", err);
                                        break 'outer;
                                    }
                                }
                            }
                            Event::Upgrade(channel) => {
                                if channel.send(stream_tx).is_err() {
                                    debug!("Failed to send stream.");
                                    break 'outer;
                                }
                                if let Some(stream_) = rx.recv().await {
                                    stream = stream_;
                                    continue 'outer;
                                } else {
                                    break 'outer;
                                }
                            }
                            _ => {
                                stream = event;
                                continue 'outer;
                            }
                        }
                    }
                    break 'outer;
                }
                Event::StreamTls(mut stream_tx) => {
                    while let Some(event) = rx.recv().await {
                        match event {
                            Event::Bytes(bytes) => {
                                match stream_tx.write_all(bytes.as_ref()).await {
                                    Ok(_) => {
                                        let _ = stream_tx.flush().await;
                                    }
                                    Err(err) => {
                                        debug!("Failed to write to stream: {}", err);
                                        break 'outer;
                                    }
                                }
                            }
                            _ => {
                                stream = event;
                                continue 'outer;
                            }
                        }
                    }
                    break 'outer;
                }
                _ => unreachable!(),
            }
        }
    });
    tx
}

impl<T: AsyncRead> Session<T> {
    pub async fn write_bytes(&self, bytes: impl Into<Cow<'static, [u8]>>) -> crate::OpResult {
        let bytes = bytes.into();

        /*let c = println!(
            "-> {:?}",
            String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), 100)])
        );*/

        if let Err(err) = self.writer.send(Event::Bytes(bytes)).await {
            debug!("Failed to send bytes: {}", err);
            Err(())
        } else {
            Ok(())
        }
    }
}

impl SessionData {
    pub async fn write_bytes(&self, bytes: impl Into<Cow<'static, [u8]>>) -> bool {
        let bytes = bytes.into();
        /*let c = println!(
            "-> {:?}",
            String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), 100)])
        );*/

        if let Err(err) = self.writer.send(Event::Bytes(bytes)).await {
            debug!("Failed to send bytes: {}", err);
            false
        } else {
            true
        }
    }
}
