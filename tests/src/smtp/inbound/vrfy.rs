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

use ahash::AHashSet;

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::{
    config::ConfigContext,
    core::{Session, SMTP},
    lookup::Lookup,
};

#[tokio::test]
async fn vrfy_expn() {
    let mut core = SMTP::test();
    let mut ctx = ConfigContext::new(&[]);
    ctx.lookup.insert(
        "vrfy".to_string(),
        Arc::new(Lookup::List(AHashSet::from_iter([
            "john@foobar.org:john@foobar.org".to_string(),
            "john:john@foobar.org".to_string(),
        ]))),
    );
    ctx.lookup.insert(
        "expn".to_string(),
        Arc::new(Lookup::List(AHashSet::from_iter([
            "sales:john@foobar.org,bill@foobar.org,jane@foobar.org".to_string(),
            "support:mike@foobar.org".to_string(),
        ]))),
    );

    let mut config = &mut core.session.config.rcpt;

    config.lookup_vrfy = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 'vrfy'},
    {else = false}]"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();
    config.lookup_expn = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 'expn'},
    {else = false}]"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.lookup, "", "")
        .unwrap();

    // EHLO should not avertise VRFY/EXPN to 10.0.0.2
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("EXPN")
        .assert_not_contains("VRFY");
    session.cmd("VRFY john", "252 2.5.1").await;
    session.cmd("EXPN sales", "252 2.5.1").await;

    // EHLO should advertise VRFY/EXPN for 10.0.0.1
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("EXPN")
        .assert_contains("VRFY");

    // Successful VRFY
    session.cmd("VRFY john", "250 john@foobar.org").await;

    // Successful EXPN
    session
        .cmd("EXPN sales", "250")
        .await
        .assert_contains("250-john@foobar.org")
        .assert_contains("250-bill@foobar.org")
        .assert_contains("250 jane@foobar.org");

    // Non-existent VRFY
    session.cmd("VRFY bill", "550 5.1.2").await;

    // Non-existent EXPN
    session.cmd("EXPN procurement", "550 5.1.2").await;
}
