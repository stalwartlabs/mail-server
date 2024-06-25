/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::Core;

use mail_auth::{
    common::{parse::TxtRecordParser, verify::DomainKey},
    spf::Spf,
};
use store::Stores;
use utils::config::Config;

use crate::smtp::{
    build_smtp,
    inbound::TestMessage,
    session::{TestSession, VerifyResponse},
    TempDir, TestSMTP,
};
use smtp::core::{Inner, Session};

pub const SIGNATURES: &str = "
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
private-key = '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAO3hAf144lTAVjTkht3ZwBTK0CMCCd1bI0alggneN3B
-----END PRIVATE KEY-----'
domain = 'example.com'
selector = 'ed'
headers = ['From', 'To', 'Date', 'Subject', 'Message-ID']
algorithm = 'ed25519-sha256'
canonicalization = 'relaxed/simple'
set-body-length = false
";

const CONFIG: &str = r#"
[storage]
data = "sqlite"
lookup = "sqlite"
blob = "sqlite"
fts = "sqlite"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/queue.db"

[directory."local"]
type = "memory"

[[directory."local".principals]]
name = "john"
description = "John Doe"
secret = "secret"
email = ["jdoe@example.com"]

[session.rcpt]
directory = "'local'"

[session.data.add-headers]
received = true
received-spf = true
auth-results = true
message-id = true
date = true
return-path = false

[auth.spf.verify]
ehlo = "relaxed"
mail-from = "relaxed"

[auth.dkim]
verify = "relaxed"
sign = "['rsa']"

[auth.arc]
verify = "relaxed"
seal = "'ed'"

[auth.dmarc]
verify = "relaxed"

"#;

#[tokio::test]
async fn sign_and_seal() {
    // Enable logging
    /*let disable = "true";
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    let tmp_dir = TempDir::new("smtp_sign_test", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG.to_string() + SIGNATURES)).unwrap();
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;
    let mut inner = Inner::default();

    // Create temp dir for queue
    let mut qr = inner.init_test_queue(&core);

    // Add SPF, DKIM and DMARC records
    core.smtp.resolvers.dns.txt_add(
        "mx.example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
        "example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
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
    core.smtp.resolvers.dns.txt_add(
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

    // Test DKIM signing
    let mut session = Session::test(build_smtp(core, inner));
    session.data.remote_ip_str = "10.0.0.2".to_string();
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
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains(
            "DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com; c=simple/relaxed;",
        );

    // Test ARC verify and seal
    session
        .send_message("bill@foobar.org", &["jdoe@example.com"], "test:arc", "250")
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("ARC-Seal: i=3; a=ed25519-sha256; s=ed; d=example.com; cv=pass;")
        .assert_contains(
            "ARC-Message-Signature: i=3; a=ed25519-sha256; s=ed; d=example.com; c=relaxed/simple;",
        );

    // Test ARC sealing of a DKIM signed message
    session
        .send_message("bill@foobar.org", &["jdoe@example.com"], "test:dkim", "250")
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("ARC-Seal: i=1; a=ed25519-sha256; s=ed; d=example.com; cv=none;")
        .assert_contains(
            "ARC-Message-Signature: i=1; a=ed25519-sha256; s=ed; d=example.com; c=relaxed/simple;",
        );
}
