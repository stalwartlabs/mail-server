/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use crate::smtp::{TempDir, TestSMTP, session::TestSession};
use common::Core;
use smtp::core::{Session, SessionAddress};
use store::Stores;
use utils::config::Config;

const CONFIG: &str = r#"
[storage]
data = "rocksdb"
lookup = "rocksdb"
blob = "rocksdb"
fts = "rocksdb"

[store."rocksdb"]
type = "rocksdb"
path = "{TMP}/data.db"

[[queue.limiter.inbound]]
match = "remote_ip = '10.0.0.1'"
key = 'remote_ip'
rate = '2/1s'
enable = true

[[queue.limiter.inbound]]
key = 'sender'
rate = '2/1s'
enable = true

[[queue.limiter.inbound]]
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
    let stores = Stores::parse_all(&mut config, false).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;

    // Test connection rate limit
    let mut session = Session::test(TestSMTP::from_core(core).server);
    session.data.remote_ip_str = "10.0.0.1".into();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        session.is_allowed().await,
        "Rate limiter did not restore quota."
    );

    // Test mail from rate limit
    session.data.mail_from = SessionAddress {
        address: "sender@test.org".into(),
        address_lcase: "sender@test.org".into(),
        domain: "test.org".into(),
        flags: 0,
        dsn_info: None,
    }
    .into();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.data.mail_from = SessionAddress {
        address: "other-sender@test.org".into(),
        address_lcase: "other-sender@test.org".into(),
        domain: "test.org".into(),
        flags: 0,
        dsn_info: None,
    }
    .into();
    assert!(session.is_allowed().await, "Rate limiter failed.");

    // Test recipient rate limit
    session.data.rcpt_to.push(SessionAddress {
        address: "recipient@example.org".into(),
        address_lcase: "recipient@example.org".into(),
        domain: "example.org".into(),
        flags: 0,
        dsn_info: None,
    });
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(session.is_allowed().await, "Rate limiter too strict.");
    assert!(!session.is_allowed().await, "Rate limiter failed.");
    session.data.remote_ip_str = "10.0.0.2".into();
    assert!(session.is_allowed().await, "Rate limiter too strict.");
}
