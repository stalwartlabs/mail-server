/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{path::PathBuf, time::SystemTime};

use crate::config::telemetry::{LogTracer, RotationStrategy};

use mail_parser::DateTime;
use tokio::{
    fs::{File, OpenOptions},
    io::BufWriter,
};
use trc::{ipc::subscriber::SubscriberBuilder, serializers::text::FmtWriter, TelemetryEvent};

pub(crate) fn spawn_log_tracer(builder: SubscriberBuilder, settings: LogTracer) {
    let (_, mut rx) = builder.register();
    tokio::spawn(async move {
        if let Some(writer) = settings.build_writer().await {
            let mut buf = FmtWriter::new(writer)
                .with_ansi(settings.ansi)
                .with_multiline(settings.multiline);
            let mut roatation_timestamp = settings.next_rotation();

            while let Some(events) = rx.recv().await {
                for event in events {
                    // Check if we need to rotate the log file
                    if roatation_timestamp != 0 && event.inner.timestamp > roatation_timestamp {
                        if let Err(err) = buf.flush().await {
                            trc::event!(
                                Telemetry(TelemetryEvent::LogError),
                                Reason = err.to_string(),
                                Details = "Failed to flush log buffer"
                            );
                        }

                        if let Some(writer) = settings.build_writer().await {
                            buf.update_writer(writer);
                            roatation_timestamp = settings.next_rotation();
                        } else {
                            return;
                        };
                    }

                    if let Err(err) = buf.write(&event).await {
                        trc::event!(
                            Telemetry(TelemetryEvent::LogError),
                            Reason = err.to_string(),
                            Details = "Failed to write event to log"
                        );
                        return;
                    }
                }

                if let Err(err) = buf.flush().await {
                    trc::event!(
                        Telemetry(TelemetryEvent::LogError),
                        Reason = err.to_string(),
                        Details = "Failed to flush log buffer"
                    );
                }
            }
        }
    });
}

impl LogTracer {
    pub async fn build_writer(&self) -> Option<BufWriter<File>> {
        let now = DateTime::from_timestamp(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64,
        );
        let file_name = match self.rotate {
            RotationStrategy::Daily => {
                format!(
                    "{}.{:04}-{:02}-{:02}",
                    self.prefix, now.year, now.month, now.day
                )
            }
            RotationStrategy::Hourly => {
                format!(
                    "{}.{:04}-{:02}-{:02}T{:02}",
                    self.prefix, now.year, now.month, now.day, now.hour
                )
            }
            RotationStrategy::Minutely => {
                format!(
                    "{}.{:04}-{:02}-{:02}T{:02}:{:02}",
                    self.prefix, now.year, now.month, now.day, now.hour, now.minute
                )
            }
            RotationStrategy::Never => self.prefix.clone(),
        };
        let path = PathBuf::from(&self.path).join(file_name);

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
        {
            Ok(writer) => Some(BufWriter::new(writer)),
            Err(err) => {
                trc::event!(
                    Telemetry(TelemetryEvent::LogError),
                    Details = "Failed to create log file",
                    Path = path.to_string_lossy().into_owned(),
                    Reason = err.to_string(),
                );
                None
            }
        }
    }

    pub fn next_rotation(&self) -> u64 {
        let mut now = DateTime::from_timestamp(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64,
        );

        now.second = 0;

        match self.rotate {
            RotationStrategy::Daily => {
                now.hour = 0;
                now.minute = 0;
                now.to_timestamp() as u64 + 86400
            }
            RotationStrategy::Hourly => {
                now.minute = 0;
                now.to_timestamp() as u64 + 3600
            }
            RotationStrategy::Minutely => now.to_timestamp() as u64 + 60,
            RotationStrategy::Never => 0,
        }
    }
}
