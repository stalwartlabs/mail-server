/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    io::{stderr, Error},
    pin::Pin,
    task::{Context, Poll},
};

use crate::config::telemetry::ConsoleTracer;
use std::io::Write;
use tokio::io::AsyncWrite;
use trc::{ipc::subscriber::SubscriberBuilder, serializers::text::FmtWriter};

pub(crate) fn spawn_console_tracer(builder: SubscriberBuilder, settings: ConsoleTracer) {
    let (_, mut rx) = builder.register();
    tokio::spawn(async move {
        let mut buf = FmtWriter::new(StdErrWriter::default())
            .with_ansi(settings.ansi)
            .with_multiline(settings.multiline);

        while let Some(events) = rx.recv().await {
            for event in events {
                let _ = buf.write(&event).await;

                if !settings.buffered {
                    let _ = buf.flush().await;
                }
            }

            if settings.buffered {
                let _ = buf.flush().await;
            }
        }
    });
}

const BUFFER_CAPACITY: usize = 4096;

pub struct StdErrWriter {
    buffer: Vec<u8>,
}

impl AsyncWrite for StdErrWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let bytes_len = bytes.len();
        let buffer_len = self.buffer.len();

        if buffer_len + bytes_len < BUFFER_CAPACITY {
            self.buffer.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes_len))
        } else if bytes_len > BUFFER_CAPACITY {
            let result = stderr()
                .write_all(&self.buffer)
                .and_then(|_| stderr().write_all(bytes));
            self.buffer.clear();
            Poll::Ready(result.map(|_| bytes_len))
        } else {
            let result = stderr().write_all(&self.buffer);
            self.buffer.clear();
            self.buffer.extend_from_slice(bytes);
            Poll::Ready(result.map(|_| bytes_len))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(if !self.buffer.is_empty() {
            let result = stderr().write_all(&self.buffer);
            self.buffer.clear();
            result
        } else {
            Ok(())
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Default for StdErrWriter {
    fn default() -> Self {
        Self {
            buffer: Vec::with_capacity(BUFFER_CAPACITY),
        }
    }
}
