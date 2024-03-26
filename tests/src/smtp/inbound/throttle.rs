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

use std::time::Duration;

use crate::smtp::{build_smtp, session::TestSession, TempDir};
use common::Core;
use smtp::core::{Inner, Session, SessionAddress};
use store::Stores;
use utils::config::Config;

const CONFIG: &str = r#"
[storage]
data = "sqlite"
lookup = "sqlite"
blob = "sqlite"
fts = "sqlite"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/data.db"

[[session.throttle]]
match = "remote_ip = '10.0.0.1'"
key = 'remote_ip'
concurrency = 2
rate = '3/1s'
enable = true

[[session.throttle]]
key = 'sender'
rate = '2/1s'
enable = true

[[session.throttle]]
key = ['remote_ip', 'rcpt']
rate = '2/1s'
enable = true

"#;

#[tokio::test]
async fn throttle_inbound() {
    // Enable logging
    /*let disable = "true";
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    let tmp_dir = TempDir::new("smtp_inbound_throttle", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG)).unwrap();
    let stores = Stores::parse(&mut config).await;
    let core = Core::parse(&mut config, stores).await;
    let inner = Inner::default();

    // Test connection concurrency limit
    let mut session = Session::test(build_smtp(core, inner));
    session.data.remote_ip_str = "10.0.0.1".to_string();
    assert!(
        session.is_allowed().await,
        "Concurrency limiter too strict."
    );
    assert!(
        session.is_allowed().await,
        "Concurrency limiter too strict."
    );
    assert!(!session.is_allowed().await, "Concurrency limiter failed.");

    // Test connection rate limit
    session.in_flight.clear(); // Manually reset concurrency limiter
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.in_flight.clear();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        session.is_allowed().await,
        "Rate limiter did not restore quota."
    );

    // Test mail from rate limit
    session.data.mail_from = SessionAddress {
        address: "sender@test.org".to_string(),
        address_lcase: "sender@test.org".to_string(),
        domain: "test.org".to_string(),
        flags: 0,
        dsn_info: None,
    }
    .into();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.data.mail_from = SessionAddress {
        address: "other-sender@test.org".to_string(),
        address_lcase: "other-sender@test.org".to_string(),
        domain: "test.org".to_string(),
        flags: 0,
        dsn_info: None,
    }
    .into();
    assert!(session.is_allowed().await, "Rate limiter failed.");

    // Test recipient rate limit
    session.data.rcpt_to.push(SessionAddress {
        address: "recipient@example.org".to_string(),
        address_lcase: "recipient@example.org".to_string(),
        domain: "example.org".to_string(),
        flags: 0,
        dsn_info: None,
    });
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.data.remote_ip_str = "10.0.0.2".to_string();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
}
