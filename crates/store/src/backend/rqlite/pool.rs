/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rqlite_rs::client::RqliteClient;
use rqlite_rs::error::{ClientBuilderError, RequestError};
use rqlite_rs::RqliteClientBuilder;
use std::fmt;

/// An `r2d2::ManageConnection` for `rusqlite::Connection`s.
pub struct RqliteConnectionManager {
    endpoints: Vec<String>,
}

impl fmt::Debug for RqliteConnectionManager {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("SqliteConnectionManager");
        let _ = builder.field("endpoints", &self.endpoints);
        builder.finish()
    }
}

impl RqliteConnectionManager {
    /// Creates a new `RqliteConnectionManager` from endpoints.
    pub fn endpoints(endpoints: Vec<String>) -> Self {
        Self {
            endpoints: endpoints,
        }
    }
}

fn sleeper(_: i32) -> bool {
    std::thread::sleep(std::time::Duration::from_millis(200));
    true
}

impl r2d2::ManageConnection for RqliteConnectionManager {
    type Connection = RqliteClient;
    type Error = ClientBuilderError;

    fn connect(&self) -> Result<RqliteClient, ClientBuilderError> {
        let mut client_builder = RqliteClientBuilder::new();

        for endpoint in &self.endpoints {
            client_builder = client_builder.known_host(endpoint);
        }

        client_builder.build().map_err(Into::into)
    }

    fn is_valid(&self, conn: &mut RqliteClient) -> Result<(), ClientBuilderError> {
        Ok(())
        /*let res = conn.exec(rqlite_rs::query!("SELECT 1;"));
        match res.wait().map_err(Into::into) {
            Ok(_) => Ok(()),
            Err(err) => Err(err)
        }*/
    }

    fn has_broken(&self, _: &mut RqliteClient) -> bool {
        false
    }
}
