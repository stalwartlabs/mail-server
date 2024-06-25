/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::Core;
use tokio::sync::watch;

use smtp::core::{Inner, Session};
use utils::config::Config;

use crate::smtp::{
    build_smtp,
    session::{TestSession, VerifyResponse},
};

const CONFIG: &str = r#"
[session]
transfer-limit = [{if = "remote_ip = '10.0.0.1'", then = 10},
                 {else = 1024}]
timeout = [{if = "remote_ip = '10.0.0.2'", then = '500ms'},
           {else = '30m'}]
duration = [{if = "remote_ip = '10.0.0.3'", then = '500ms'},
            {else = '60m'}]
"#;

#[tokio::test]
async fn limits() {
    let mut config = Config::new(CONFIG).unwrap();
    let core = Core::parse(&mut config, Default::default(), Default::default()).await;

    let (_tx, rx) = watch::channel(true);

    // Exceed max line length
    let mut session = Session::test_with_shutdown(build_smtp(core, Inner::default()), rx);
    session.data.remote_ip_str = "10.0.0.1".to_string();
    let mut buf = vec![b'A'; 2049];
    session.ingest(&buf).await.unwrap();
    session.ingest(b"\r\n").await.unwrap();
    session.response().assert_code("554 5.3.4");

    // Invalid command
    buf.extend_from_slice(b"\r\n");
    session.ingest(&buf).await.unwrap();
    session.response().assert_code("500 5.5.1");

    // Exceed transfer quota
    session.eval_session_params().await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("451 4.7.28");

    // Loitering
    session.data.remote_ip_str = "10.0.0.3".to_string();
    session.data.valid_until = Instant::now();
    session.eval_session_params().await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("453 4.3.2");

    // Timeout
    session.data.remote_ip_str = "10.0.0.2".to_string();
    session.data.valid_until = Instant::now();
    session.eval_session_params().await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("221 2.0.0");
}
