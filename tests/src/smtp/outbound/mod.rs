/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::sync::Arc;

use tokio::sync::watch;

use ::smtp::core::{Core, HttpAdminSessionManager, SmtpSessionManager};
use utils::config::{Config, ServerProtocol};

use super::add_test_certs;

pub mod dane;
pub mod extensions;
pub mod lmtp;
pub mod mta_sts;
pub mod smtp;
pub mod throttle;

const SERVER: &str = "
[server]
hostname = 'mx.example.org'
greeting = 'Test SMTP instance'
protocol = 'smtp'

[server.listener.smtp-debug]
bind = ['127.0.0.1:9925']

[server.listener.lmtp-debug]
bind = ['127.0.0.1:9924']
protocol = 'lmtp'
tls.implicit = true

[server.listener.management-debug]
bind = ['127.0.0.1:9980']
protocol = 'http'

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = 'default'

[certificate.default]
cert = 'file://{CERT}'
private-key = 'file://{PK}'
";

pub fn start_test_server(core: Arc<Core>, protocols: &[ServerProtocol]) -> watch::Sender<bool> {
    // Spawn listeners
    let config = Config::parse(&add_test_certs(SERVER)).unwrap();
    let servers = config.parse_servers().unwrap();

    // Start servers
    let smtp_manager = SmtpSessionManager::new(core.clone());
    let smtp_admin_manager = HttpAdminSessionManager::new(core);
    servers.spawn(&config, |server, shutdown_rx| {
        if protocols.contains(&server.protocol) {
            match &server.protocol {
                ServerProtocol::Smtp | ServerProtocol::Lmtp => {
                    server.spawn(smtp_manager.clone(), shutdown_rx)
                }
                ServerProtocol::Http => server.spawn(smtp_admin_manager.clone(), shutdown_rx),
                ServerProtocol::Imap | ServerProtocol::Jmap => unreachable!(),
            };
        }
    })
}
