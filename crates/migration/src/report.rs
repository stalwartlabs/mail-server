/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::LegacyBincode;
use common::Server;
use mail_auth::report::{Feedback, Report, tlsrpt::TlsReport};
use smtp::reporting::analysis::IncomingReport;
use store::{
    IterateParams, SUBSPACE_REPORT_OUT, Serialize, U64_LEN, ValueKey,
    ahash::AHashSet,
    write::{
        AlignedBytes, AnyKey, Archive, Archiver, BatchBuilder, ReportClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use trc::AddContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReportType {
    Dmarc,
    Tls,
    Arf,
}

pub(crate) async fn migrate_reports(server: &Server) -> trc::Result<()> {
    let mut num_dmarc = 0;
    let mut num_tls = 0;
    let mut num_arf = 0;

    for report in [ReportType::Dmarc, ReportType::Tls, ReportType::Arf] {
        let (from_key, to_key) = match report {
            ReportType::Dmarc => (
                ValueKey::from(ValueClass::Report(ReportClass::Dmarc { id: 0, expires: 0 })),
                ValueKey::from(ValueClass::Report(ReportClass::Dmarc {
                    id: u64::MAX,
                    expires: u64::MAX,
                })),
            ),
            ReportType::Tls => (
                ValueKey::from(ValueClass::Report(ReportClass::Tls { id: 0, expires: 0 })),
                ValueKey::from(ValueClass::Report(ReportClass::Tls {
                    id: u64::MAX,
                    expires: u64::MAX,
                })),
            ),
            ReportType::Arf => (
                ValueKey::from(ValueClass::Report(ReportClass::Arf { id: 0, expires: 0 })),
                ValueKey::from(ValueClass::Report(ReportClass::Arf {
                    id: u64::MAX,
                    expires: u64::MAX,
                })),
            ),
        };

        let mut results = AHashSet::new();

        server
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).no_values(),
                |key, _| {
                    results.insert((
                        report,
                        key.deserialize_be_u64(U64_LEN + 1)?,
                        key.deserialize_be_u64(1)?,
                    ));

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        for (report, id, expires) in results {
            match report {
                ReportType::Dmarc => {
                    match server
                        .store()
                        .get_value::<LegacyBincode<IncomingReport<Report>>>(ValueKey::from(
                            ValueClass::Report(ReportClass::Dmarc { id, expires }),
                        ))
                        .await
                    {
                        Ok(Some(bincoded)) => {
                            let mut batch = BatchBuilder::new();
                            batch.set(
                                ValueClass::Report(ReportClass::Dmarc { id, expires }),
                                Archiver::new(bincoded.inner)
                                    .serialize()
                                    .caused_by(trc::location!())?,
                            );
                            num_dmarc += 1;
                            server
                                .store()
                                .write(batch.build_all())
                                .await
                                .caused_by(trc::location!())?;
                        }
                        Ok(None) => (),
                        Err(err) => {
                            if server
                                .store()
                                .get_value::<Archive<AlignedBytes>>(ValueKey::from(
                                    ValueClass::Report(ReportClass::Dmarc { id, expires }),
                                ))
                                .await
                                .is_err()
                            {
                                return Err(err.ctx(trc::Key::Id, id).caused_by(trc::location!()));
                            }
                        }
                    }
                }
                ReportType::Tls => {
                    match server
                        .store()
                        .get_value::<LegacyBincode<IncomingReport<TlsReport>>>(ValueKey::from(
                            ValueClass::Report(ReportClass::Tls { id, expires }),
                        ))
                        .await
                    {
                        Ok(Some(bincoded)) => {
                            let mut batch = BatchBuilder::new();
                            batch.set(
                                ValueClass::Report(ReportClass::Tls { id, expires }),
                                Archiver::new(bincoded.inner)
                                    .serialize()
                                    .caused_by(trc::location!())?,
                            );
                            num_tls += 1;
                            server
                                .store()
                                .write(batch.build_all())
                                .await
                                .caused_by(trc::location!())?;
                        }
                        Ok(None) => (),
                        Err(err) => {
                            if server
                                .store()
                                .get_value::<Archive<AlignedBytes>>(ValueKey::from(
                                    ValueClass::Report(ReportClass::Tls { id, expires }),
                                ))
                                .await
                                .is_err()
                            {
                                return Err(err.ctx(trc::Key::Id, id).caused_by(trc::location!()));
                            }
                        }
                    }
                }
                ReportType::Arf => {
                    match server
                        .store()
                        .get_value::<LegacyBincode<IncomingReport<Feedback>>>(ValueKey::from(
                            ValueClass::Report(ReportClass::Arf { id, expires }),
                        ))
                        .await
                    {
                        Ok(Some(bincoded)) => {
                            let mut batch = BatchBuilder::new();
                            batch.set(
                                ValueClass::Report(ReportClass::Arf { id, expires }),
                                Archiver::new(bincoded.inner)
                                    .serialize()
                                    .caused_by(trc::location!())?,
                            );
                            num_arf += 1;
                            server
                                .store()
                                .write(batch.build_all())
                                .await
                                .caused_by(trc::location!())?;
                        }
                        Ok(None) => (),
                        Err(err) => {
                            if server
                                .store()
                                .get_value::<Archive<AlignedBytes>>(ValueKey::from(
                                    ValueClass::Report(ReportClass::Arf { id, expires }),
                                ))
                                .await
                                .is_err()
                            {
                                return Err(err.ctx(trc::Key::Id, id).caused_by(trc::location!()));
                            }
                        }
                    }
                }
            }
        }
    }

    // Delete outgoing reports
    server
        .store()
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_REPORT_OUT,
                key: KeySerializer::new(U64_LEN).write(0u8).finalize(),
            },
            AnyKey {
                subspace: SUBSPACE_REPORT_OUT,
                key: KeySerializer::new(U64_LEN)
                    .write(&[u8::MAX; 16][..])
                    .finalize(),
            },
        )
        .await
        .caused_by(trc::location!())?;

    if num_dmarc > 0 || num_tls > 0 || num_arf > 0 {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details =
                format!("Migrated {num_dmarc} DMARC, {num_tls} TLS, and {num_arf} ARF reports")
        );
    }

    Ok(())
}
