/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
    crate::enable_logging();

    let tmp_dir = TempDir::new("smtp_inbound_throttle", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG)).unwrap();
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;
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
