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

use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::core::{Session, SMTP};

#[tokio::test]
async fn limits() {
    let mut core = SMTP::test();
    let config = &mut core.core.smtp.session;
    config.transfer_limit = r#"[{if = "remote_ip = '10.0.0.1'", then = 10},
    {else = 1024}]"#
        .parse_if();
    config.timeout = r#"[{if = "remote_ip = '10.0.0.2'", then = '500ms'},
    {else = '30m'}]"#
        .parse_if();
    config.duration = r#"[{if = "remote_ip = '10.0.0.3'", then = '500ms'},
    {else = '60m'}]"#
        .parse_if();
    let (_tx, rx) = watch::channel(true);

    // Exceed max line length
    let mut session = Session::test_with_shutdown(core, rx);
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
