/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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

                                //let c = print!("{}", String::from_utf8_lossy(&bytes));

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
                                tracing::trace!(
                                    parent: &span,
                                    event = "write",
                                    data = std::str::from_utf8(bytes.as_ref()).unwrap_or_default(),
                                    size = bytes.len()
                                );

                                //let c = print!("{}", String::from_utf8_lossy(&bytes));

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
