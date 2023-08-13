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

use directory::config::ConfigDirectory;
use mail_auth::{
    common::{parse::TxtRecordParser, verify::DomainKey},
    spf::Spf,
};
use utils::config::{Config, DynValue};

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent},
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig, TestSMTP,
};
use smtp::{
    config::{
        auth::ConfigAuth, ConfigContext, EnvelopeKey, IfBlock, MaybeDynValue, VerifyStrategy,
    },
    core::{Session, SMTP},
};

const SIGNATURES: &str = "
[signature.rsa]
private-key = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv9XYXG3uK95115mB4nJ37nGeNe2CrARm1agrbcnSk5oIaEfM
ZLUR/X8gPzoiNHZcfMZEVR6bAytxUhc5EvZIZrjSuEEeny+fFd/cTvcm3cOUUbIa
UmSACj0dL2/KwW0LyUaza9z9zor7I5XdIl1M53qVd5GI62XBB76FH+Q0bWPZNkT4
NclzTLspD/MTpNCCPhySM4Kdg5CuDczTH4aNzyS0TqgXdtw6A4Sdsp97VXT9fkPW
9rso3lrkpsl/9EQ1mR/DWK6PBmRfIuSFuqnLKY6v/z2hXHxF7IoojfZLa2kZr9Ae
d4l9WheQOTA19k5r2BmlRw/W9CrgCBo0Sdj+KQIDAQABAoIBAFPChEi/OvnulReB
ECQWhOUYuNKlFKQU++2YEvZJ4+bMn5UgnE7wfJ1pj2Pr9xlfALz+OMHNrjMxGbaV
KzdrT2uCkYcf78XjnhuH9gKIiXDUv4L4N+P3u6w8yOx4bFgOS9IjS53yDOPM7SC5
g6dIg5aigHaHlffqIuFFv4yQMI/+Ai+zBKxS7wRhxK/7nnAuo28fe5MEdp57ho9/
AGlDNsdg9zCgjwhokwFE3+AaD+bkUFm4gQ1XjkUFrlmnQn8vDQ0i9toEWhCj+UPY
iOKL63MJnr90MXTXWLHoFj99wBp//mYygbF9Lj8fa28/oa8LWp3Jhb7QeMgH46iv
3aLHbTECgYEA5M2dAw+nyMw9vYlkMejhwObKYP8Mr/6zcGMLCalYvRJM5iUAM0JI
H6sM6pV9/nv167cbKocj3xYPdtE7FPOn4132MLM8Ne1f8nPE64Qrcbj5WBXvLnU8
hpWbwe2Z8h7UUMKx6q4F1/TXYkc3ScxYwfjM4mP/pLsAOgVzRSEEgrUCgYEA1qNQ
xaQHNWZ1O8WuTnqWd5JSsic6iURAmUcLeFDZY2PWhVoaQ8L/xMQhDYs1FIbLWArW
4Qq3Ibu8AbSejAKuaJz7Uf26PX+PYVUwAOO0qamCJ8d/qd6So7qWMDyAY2yXI39Y
1nMqRjr7bkEsggAZao7BKqA7ZtmogjOusBT38iUCgYEA06agJ8TDoKvOMRZ26PRU
YO0dKLzGL8eclcoI29cbj0rud7aiiMg3j5PbTuUat95TjsjDCIQaWrM9etvxm2AJ
Xfn9Uu96MyhyKQWOk46f4YMKpMElkARDCPw8KRhx39dE77AqhLyWCz8iPndCXbH6
KPTOEl4OjYOuof2Is9nnIkECgYBh948RdsnXhNlzm8nwhiGRmBbou+EK8D0v+O5y
Tyy6IcKzgSnFzgZh8EdJ4EUtBk1f9SqY8wQdgIvSl3daXorusuA/TzkngsaV3YUY
ktZOLlF7CKLrjOyPkMWmZKcROmpNyH1q/IvKHHfQnizLdXIkYd4nL5WNX0F7lE1i
j1+QhQKBgB2lviBK7rJFwlFYdQUP1NAN2dKxMZk8uJS8JglHrM0+8nRI83HbTdEQ
vB0ManEKBkbS4T5n+gRtdEqKSDmWDTXDlrBfcdCHNQLwYtBpOotCqQn/AmfjcPBl
byAbwh4+HiZ5JISoRZpiZqy67aJNVoXmdtb/E9mi7ozzytpxMNql
-----END RSA PRIVATE KEY-----'''
domain = 'example.com'
selector = 'rsa'
headers = ['From', 'To', 'Date', 'Subject', 'Message-ID']
algorithm = 'rsa-sha256'
canonicalization = 'simple/relaxed'
expire = '10d'
set-body-length = true
report = true

[signature.ed]
public-key = '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='
private-key = '-----BEGIN PRIVATE KEY-----
nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=
-----END PRIVATE KEY-----'
domain = 'example.com'
selector = 'ed'
headers = ['From', 'To', 'Date', 'Subject', 'Message-ID']
algorithm = 'ed25519-sha256'
canonicalization = 'relaxed/simple'
set-body-length = false
";

const DIRECTORY: &str = r#"
[directory."local"]
type = "memory"

[[directory."local".users]]
name = "john"
description = "John Doe"
secret = "secret"
email = ["jdoe@example.com"]

[directory."local".lookup]
domains = ["example.com"]
"#;

#[tokio::test]
async fn sign_and_seal() {
    let mut core = SMTP::test();

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_sign_test");

    // Add SPF, DKIM and DMARC records
    core.resolvers.dns.txt_add(
        "mx.example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "ed._domainkey.scamorza.org",
        DomainKey::parse(
            concat!(
                "v=DKIM1; k=ed25519; ",
                "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "rsa._domainkey.manchego.org",
        DomainKey::parse(
            concat!(
                "v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
                "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt",
                "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v",
                "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi",
                "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    let directory = Config::parse(DIRECTORY).unwrap().parse_directory().unwrap();
    let config = &mut core.session.config.rcpt;
    config.directory = IfBlock::new(Some(MaybeDynValue::Static(
        directory.directories.get("local").unwrap().clone(),
    )));

    let config = &mut core.session.config;
    config.data.add_auth_results = IfBlock::new(true);
    config.data.add_date = IfBlock::new(true);
    config.data.add_message_id = IfBlock::new(true);
    config.data.add_received = IfBlock::new(true);
    config.data.add_return_path = IfBlock::new(true);
    config.data.add_received_spf = IfBlock::new(true);

    let config = &mut core.mail_auth;
    let ctx = ConfigContext::new(&[]).parse_signatures();
    config.spf.verify_ehlo = IfBlock::new(VerifyStrategy::Relaxed);
    config.spf.verify_mail_from = config.spf.verify_ehlo.clone();
    config.dkim.verify = config.spf.verify_ehlo.clone();
    config.arc.verify = config.spf.verify_ehlo.clone();
    config.dmarc.verify = config.spf.verify_ehlo.clone();
    config.dkim.sign = "['rsa']"
        .parse_if::<Vec<DynValue<EnvelopeKey>>>(&ctx)
        .map_if_block(&ctx.signers, "", "")
        .unwrap();
    config.arc.seal = "'ed'"
        .parse_if::<Option<DynValue<EnvelopeKey>>>(&ctx)
        .map_if_block(&ctx.sealers, "", "")
        .unwrap();

    // Test DKIM signing
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.example.com").await;
    session
        .send_message(
            "bill@foobar.org",
            &["jdoe@example.com"],
            "test:no_dkim",
            "250",
        )
        .await;
    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains(
            "DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com; c=simple/relaxed;",
        );

    // Test ARC verify and seal
    session
        .send_message("bill@foobar.org", &["jdoe@example.com"], "test:arc", "250")
        .await;
    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("ARC-Seal: i=3; a=ed25519-sha256; s=ed; d=example.com; cv=pass;")
        .assert_contains(
            "ARC-Message-Signature: i=3; a=ed25519-sha256; s=ed; d=example.com; c=relaxed/simple;",
        );
}

pub trait TextConfigContext<'x> {
    fn parse_signatures(self) -> ConfigContext<'x>;
}

impl<'x> TextConfigContext<'x> for ConfigContext<'x> {
    fn parse_signatures(mut self) -> Self {
        Config::parse(SIGNATURES)
            .unwrap()
            .parse_signatures(&mut self)
            .unwrap();
        self
    }
}
