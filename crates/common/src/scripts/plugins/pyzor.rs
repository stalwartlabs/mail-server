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

use sieve::{runtime::Variable, FunctionMap};

use super::PluginContext;

use std::{
    borrow::Cow,
    io::Write,
    time::{Duration, SystemTime},
};

use mail_parser::{decoders::html::add_html_token, Message, PartType};
use nlp::tokenizers::types::{TokenType, TypesTokenizer};
use sha1::{Digest, Sha1};
use tokio::net::UdpSocket;
use utils::suffixlist::PublicSuffix;

const MIN_LINE_LENGTH: usize = 8;
const ATOMIC_NUM_LINES: usize = 4;
const DIGEST_SPEC: &[(usize, usize)] = &[(20, 3), (60, 3)];

#[derive(Default, Debug, PartialEq, Eq)]
struct PyzorResponse {
    code: u32,
    count: u64,
    wl_count: u64,
}

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("pyzor_check", plugin_id, 2);
}

pub async fn exec(ctx: PluginContext<'_>) -> Variable {
    // Make sure there is at least one text part
    if !ctx
        .message
        .parts
        .iter()
        .any(|p| matches!(p.body, PartType::Text(_) | PartType::Html(_)))
    {
        return Variable::default();
    }

    // Hash message
    let request = ctx
        .message
        .pyzor_check_message(&ctx.core.smtp.resolvers.psl);

    #[cfg(feature = "test_mode")]
    {
        if request.contains("b5b476f0b5ba6e1c038361d3ded5818dd39c90a2") {
            return PyzorResponse {
                code: 200,
                count: 1000,
                wl_count: 0,
            }
            .into();
        } else if request.contains("d67d4b8bfc3860449e3418bb6017e2612f3e2a99") {
            return PyzorResponse {
                code: 200,
                count: 60,
                wl_count: 10,
            }
            .into();
        } else if request.contains("81763547012b75e57a20d18ce0b93014208cdfdb") {
            return PyzorResponse {
                code: 200,
                count: 50,
                wl_count: 20,
            }
            .into();
        }
    }

    let span = ctx.span;
    let address = ctx.arguments[0].to_string();
    let timeout = Duration::from_secs((ctx.arguments[1].to_integer() as u64).clamp(5, 60));
    // Send message to address
    match pyzor_send_message(address.as_ref(), timeout, &request).await {
        Ok(response) => response.into(),
        Err(err) => {
            tracing::debug!(
                parent: span,
                context = "sieve:pyzor_check",
                event = "failed",
                reason = %err,
            );
            Variable::default()
        }
    }
}

impl From<PyzorResponse> for Variable {
    fn from(response: PyzorResponse) -> Self {
        vec![
            Variable::from(response.code),
            Variable::from(response.count),
            Variable::from(response.wl_count),
        ]
        .into()
    }
}

async fn pyzor_send_message(
    addr: &str,
    timeout: Duration,
    message: &str,
) -> std::io::Result<PyzorResponse> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    tokio::time::timeout(timeout, socket.send_to(message.as_bytes(), addr)).await??;

    let mut buffer = vec![0u8; 1024];
    let (size, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buffer)).await??;

    let raw_response = std::str::from_utf8(&buffer[..size])
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let mut response = PyzorResponse {
        code: u32::MAX,
        count: u64::MAX,
        wl_count: u64::MAX,
    };

    for line in raw_response.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("code") {
                response.code = v.trim().parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid line: {raw_response}"),
                    )
                })?;
            } else if k.eq_ignore_ascii_case("count") {
                response.count = v.trim().parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid line: {raw_response}"),
                    )
                })?;
            } else if k.eq_ignore_ascii_case("wl-count") {
                response.wl_count = v.trim().parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid line: {raw_response}"),
                    )
                })?;
            }
        }
    }

    if response.code != u32::MAX && response.count != u64::MAX && response.wl_count != u64::MAX {
        Ok(response)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid response: {raw_response}"),
        ))
    }
}

trait PyzorDigest<W: Write> {
    fn pyzor_digest(&self, writer: W, psl: &PublicSuffix) -> W;
}

pub trait PyzorCheck {
    fn pyzor_check_message(&self, psl: &PublicSuffix) -> String;
}

impl<'x, W: Write> PyzorDigest<W> for Message<'x> {
    fn pyzor_digest(&self, writer: W, psl: &PublicSuffix) -> W {
        let parts = self
            .parts
            .iter()
            .filter_map(|part| match &part.body {
                PartType::Text(text) => Some(text.as_ref().into()),
                PartType::Html(html) => Some(html_to_text(html.as_ref()).into()),
                _ => None,
            })
            .collect::<Vec<Cow<str>>>();

        pyzor_digest(writer, parts.iter().flat_map(|text| text.lines()), psl)
    }
}

impl<'x> PyzorCheck for Message<'x> {
    fn pyzor_check_message(&self, psl: &PublicSuffix) -> String {
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        pyzor_create_message(
            self,
            psl,
            time,
            (time & 0xFFFF) as u16 ^ ((time >> 16) & 0xFFFF) as u16,
        )
    }
}

fn pyzor_create_message(
    message: &Message<'_>,
    psl: &PublicSuffix,
    time: u64,
    thread: u16,
) -> String {
    // Hash message
    let hash = message.pyzor_digest(Sha1::new(), psl).finalize();
    // Hash key
    let mut hash_key = Sha1::new();
    hash_key.update("anonymous:".as_bytes());
    let hash_key = hash_key.finalize();

    // Hash message
    let message = format!(
        "Op: check\nOp-Digest: {hash:x}\nThread: {thread}\nPV: 2.1\nUser: anonymous\nTime: {time}"
    );
    let mut msg_hash = Sha1::new();
    msg_hash.update(message.as_bytes());
    let msg_hash = msg_hash.finalize();

    // Sign
    let mut sig = Sha1::new();
    sig.update(msg_hash);
    sig.update(&format!(":{time}:{hash_key:x}"));
    let sig = sig.finalize();

    format!("{message}\nSig: {sig:x}\n")
}

fn pyzor_digest<'x, I, W>(mut writer: W, lines: I, psl: &PublicSuffix) -> W
where
    I: Iterator<Item = &'x str>,
    W: Write,
{
    let mut result = Vec::with_capacity(16);

    for line in lines {
        let mut clean_line = String::with_capacity(line.len());
        let mut token_start = usize::MAX;
        let mut token_end = usize::MAX;

        let add_line = |line: &mut String, span: &str| {
            if !span.contains(char::from(0)) {
                if span.len() < 10 {
                    line.push_str(span);
                }
            } else {
                let span = span.replace(char::from(0), "");
                if span.len() < 10 {
                    line.push_str(&span);
                }
            }
        };

        for token in TypesTokenizer::new(line, psl) {
            match token.word {
                TokenType::Alphabetic(_)
                | TokenType::Alphanumeric(_)
                | TokenType::Integer(_)
                | TokenType::Float(_)
                | TokenType::Other(_)
                | TokenType::Punctuation(_) => {
                    if token_start == usize::MAX {
                        token_start = token.from;
                    }
                    token_end = token.to;
                }
                TokenType::Space
                | TokenType::Url(_)
                | TokenType::UrlNoScheme(_)
                | TokenType::UrlNoHost(_)
                | TokenType::IpAddr(_)
                | TokenType::Email(_) => {
                    if token_start != usize::MAX {
                        add_line(&mut clean_line, &line[token_start..token_end]);
                        token_start = usize::MAX;
                        token_end = usize::MAX;
                    }
                }
            }
        }

        if token_start != usize::MAX {
            add_line(&mut clean_line, &line[token_start..token_end]);
        }

        if clean_line.len() >= MIN_LINE_LENGTH {
            result.push(clean_line);
        }
    }

    if result.len() > ATOMIC_NUM_LINES {
        for (offset, length) in DIGEST_SPEC {
            for i in 0..*length {
                if let Some(line) = result.get((*offset * result.len() / 100) + i) {
                    let _ = writer.write_all(line.as_bytes());
                }
            }
        }
    } else {
        for line in result {
            let _ = writer.write_all(line.as_bytes());
        }
    }

    writer
}

fn html_to_text(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let input = input.as_bytes();

    let mut in_tag = false;
    let mut in_comment = false;
    let mut in_style = false;
    let mut in_script = false;

    let mut is_token_start = true;
    let mut is_after_space = false;
    let mut is_tag_close = false;

    let mut token_start = 0;
    let mut token_end = 0;

    let mut tag_token_pos = 0;
    let mut comment_pos = 0;

    for (pos, ch) in input.iter().enumerate() {
        if !in_comment {
            match ch {
                b'<' => {
                    if !(in_tag || in_style || in_script || is_token_start) {
                        add_html_token(
                            &mut result,
                            &input[token_start..token_end + 1],
                            is_after_space,
                        );
                        is_after_space = false;
                    }

                    tag_token_pos = 0;
                    in_tag = true;
                    is_token_start = true;
                    is_tag_close = false;
                    continue;
                }
                b'>' if in_tag => {
                    if tag_token_pos == 1 {
                        if let Some(tag) = input.get(token_start..token_end + 1) {
                            if tag.eq_ignore_ascii_case(b"style") {
                                in_style = !is_tag_close;
                            } else if tag.eq_ignore_ascii_case(b"script") {
                                in_script = !is_tag_close;
                            }
                        }
                    }

                    in_tag = false;
                    is_token_start = true;
                    is_after_space = !result.is_empty();

                    continue;
                }
                b'/' if in_tag => {
                    if tag_token_pos == 0 {
                        is_tag_close = true;
                    }
                    continue;
                }
                b'!' if in_tag && tag_token_pos == 0 => {
                    if let Some(b"--") = input.get(pos + 1..pos + 3) {
                        in_comment = true;
                        continue;
                    }
                }
                b' ' | b'\t' | b'\r' | b'\n' => {
                    if !(in_tag || in_style || in_script) {
                        if !is_token_start {
                            add_html_token(
                                &mut result,
                                &input[token_start..token_end + 1],
                                is_after_space,
                            );
                        }
                        is_after_space = true;
                    }

                    is_token_start = true;
                    continue;
                }
                b'&' if !(in_tag || is_token_start || in_style || in_script) => {
                    add_html_token(
                        &mut result,
                        &input[token_start..token_end + 1],
                        is_after_space,
                    );
                    is_token_start = true;
                    is_after_space = false;
                }
                b';' if !(in_tag || is_token_start || in_style || in_script) => {
                    add_html_token(&mut result, &input[token_start..pos + 1], is_after_space);
                    is_token_start = true;
                    is_after_space = false;
                    continue;
                }
                _ => (),
            }
            if is_token_start {
                token_start = pos;
                is_token_start = false;
                if in_tag {
                    tag_token_pos += 1;
                }
            }
            token_end = pos;
        } else {
            match ch {
                b'-' => comment_pos += 1,
                b'>' if comment_pos == 2 => {
                    comment_pos = 0;
                    in_comment = false;
                    in_tag = false;
                    is_token_start = true;
                }
                _ => comment_pos = 0,
            }
        }
    }

    if !(in_tag || is_token_start || in_style || in_script) {
        add_html_token(
            &mut result,
            &input[token_start..token_end + 1],
            is_after_space,
        );
    }

    result.shrink_to_fit();
    result
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use mail_parser::MessageParser;
    use sha1::Digest;
    use sha1::Sha1;
    use utils::suffixlist::PublicSuffix;

    use super::pyzor_create_message;
    use super::pyzor_send_message;
    use super::{html_to_text, pyzor_digest, PyzorDigest};

    use super::PyzorResponse;

    #[ignore]
    #[tokio::test]
    async fn send_message() {
        assert_eq!(
            pyzor_send_message(
                "public.pyzor.org:24441",
                Duration::from_secs(10),
                concat!(
                    "Op: check\n",
                    "Op-Digest: b2c27325a034c581df0c9ef37e4a0d63208a3e7e\n",
                    "Thread: 49005\n",
                    "PV: 2.1\n",
                    "User: anonymous\n",
                    "Time: 1697468672\n",
                    "Sig: 9cf4571b85d3887fdd0d4f444fd0c164e0290722\n"
                ),
            )
            .await
            .unwrap(),
            PyzorResponse {
                code: 200,
                count: 0,
                wl_count: 0
            }
        );
    }

    #[test]
    fn message_pyzor() {
        let mut psl = PublicSuffix::default();
        psl.suffixes.insert("com".to_string());
        let message = pyzor_create_message(
            &MessageParser::new().parse(HTML_TEXT_STYLE_SCRIPT).unwrap(),
            &psl,
            1697468672,
            49005,
        );

        assert_eq!(
            message,
            concat!(
                "Op: check\n",
                "Op-Digest: b2c27325a034c581df0c9ef37e4a0d63208a3e7e\n",
                "Thread: 49005\n",
                "PV: 2.1\n",
                "User: anonymous\n",
                "Time: 1697468672\n",
                "Sig: 9cf4571b85d3887fdd0d4f444fd0c164e0290722\n"
            )
        );
    }

    #[test]
    fn digest_pyzor() {
        let mut psl = PublicSuffix::default();
        psl.suffixes.insert("com".to_string());

        // HTML stripping
        assert_eq!(html_to_text(HTML_RAW), HTML_RAW_STRIPED);

        // Token stripping
        for strip_me in [
            "t@abc.com",
            "t1@abc.com",
            "t+a@abc.com",
            "t.a@abc.com",
            "0A2D3f%a#S",
            "3sddkf9jdkd9",
            "@@#@@@@@@@@@",
            "http://spammer.com/special-offers?buy=now",
        ] {
            assert_eq!(
                String::from_utf8(pyzor_digest(
                    Vec::new(),
                    format!("Test {strip_me} Test2").lines(),
                    &psl
                ))
                .unwrap(),
                "TestTest2"
            );
        }

        // Test short lines
        assert_eq!(
            String::from_utf8(pyzor_digest(
                Vec::new(),
                concat!("This line is included\n", "not this\n", "This also").lines(),
                &psl
            ))
            .unwrap(),
            "ThislineisincludedThisalso"
        );

        // Test atomic
        assert_eq!(
            String::from_utf8(pyzor_digest(
                Vec::new(),
                "All this message\nShould be included\nIn the digest".lines(),
                &psl
            ))
            .unwrap(),
            "AllthismessageShouldbeincludedInthedigest"
        );

        // Test spec
        let mut text = String::new();
        for i in 0..100 {
            text += format!("Line{i} test test test\n").as_str();
        }
        let mut expected = String::new();
        for i in [20, 21, 22, 60, 61, 62] {
            expected += format!("Line{i}testtesttest").as_str();
        }
        assert_eq!(
            String::from_utf8(pyzor_digest(Vec::new(), text.lines(), &psl)).unwrap(),
            expected
        );

        // Test email parsing
        for (input, expected) in [
            (
                HTML_TEXT,
                concat!(
                    "Emailspam,alsoknownasjunkemailorbulkemail,isasubset",
                    "ofspaminvolvingnearlyidenticalmessagessenttonumerous",
                    "byemail.Clickingonlinksinspamemailmaysendusersto",
                    "byemail.Clickingonlinksinspamemailmaysendusersto",
                    "phishingwebsitesorsitesthatarehostingmalware.",
                    "Emailspam.Emailspam,alsoknownasjunkemailorbulkemail,",
                    "isasubsetofspaminvolvingnearlyidenticalmessage",
                    "ssenttonumerousbyemail.Clickingonlinksinspamemailmaysenduse",
                    "rstophishingwebsitesorsitesthatarehostingmalware."
                ),
            ),
            (HTML_TEXT_STYLE_SCRIPT, "Thisisatest.Thisisatest."),
            (TEXT_ATTACHMENT, "Thisisatestmailing"),
            (TEXT_ATTACHMENT_W_NULL, "Thisisatestmailing"),
            (TEXT_ATTACHMENT_W_MULTIPLE_NULLS, "Thisisatestmailing"),
            (TEXT_ATTACHMENT_W_SUBJECT_NULL, "Thisisatestmailing"),
            (TEXT_ATTACHMENT_W_CONTENTTYPE_NULL, "Thisisatestmailing"),
        ] {
            assert_eq!(
                String::from_utf8(
                    MessageParser::new()
                        .parse(input)
                        .unwrap()
                        .pyzor_digest(Vec::new(), &psl)
                )
                .unwrap(),
                expected,
                "failed for {input}"
            )
        }

        // Test SHA hash
        assert_eq!(
            format!(
                "{:x}",
                MessageParser::new()
                    .parse(HTML_TEXT_STYLE_SCRIPT)
                    .unwrap()
                    .pyzor_digest(Sha1::new(), &psl)
                    .finalize()
            ),
            "b2c27325a034c581df0c9ef37e4a0d63208a3e7e",
        )
    }

    const HTML_TEXT: &str = r#"MIME-Version: 1.0
Sender: chirila@gapps.spamexperts.com
Received: by 10.216.157.70 with HTTP; Thu, 16 Jan 2014 00:43:31 -0800 (PST)
Date: Thu, 16 Jan 2014 10:43:31 +0200
Delivered-To: chirila@gapps.spamexperts.com
X-Google-Sender-Auth: ybCmONS9U9D6ZUfjx-9_tY-hF2Q
Message-ID: <CAK-mJS8sE-V6qtspzzZ+bZ1eSUE_FNMt3K-5kBOG-z3NMgU_Rg@mail.gmail.com>
Subject: Test
From: Alexandru Chirila <chirila@spamexperts.com>
To: Alexandru Chirila <chirila@gapps.spamexperts.com>
Content-Type: multipart/alternative; boundary=001a11c25ff293069304f0126bfd

--001a11c25ff293069304f0126bfd
Content-Type: text/plain; charset=ISO-8859-1

Email spam.

Email spam, also known as junk email or unsolicited bulk email, is a subset
of electronic spam involving nearly identical messages sent to numerous
recipients by email. Clicking on links in spam email may send users to
phishing web sites or sites that are hosting malware.

--001a11c25ff293069304f0126bfd
Content-Type: text/html; charset=ISO-8859-1
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Email spam.</div><div><br></div><div>Email spam, also=
 known as junk email or unsolicited bulk email, is a subset of electronic s=
pam involving nearly identical messages sent to numerous recipients by emai=
l. Clicking on links in spam email may send users to phishing web sites or =
sites that are hosting malware.</div>
</div>

--001a11c25ff293069304f0126bfd--
"#;

    const HTML_TEXT_STYLE_SCRIPT: &str = r#"MIME-Version: 1.0
Sender: chirila@gapps.spamexperts.com
Received: by 10.216.157.70 with HTTP; Thu, 16 Jan 2014 00:43:31 -0800 (PST)
Date: Thu, 16 Jan 2014 10:43:31 +0200
Delivered-To: chirila@gapps.spamexperts.com
X-Google-Sender-Auth: ybCmONS9U9D6ZUfjx-9_tY-hF2Q
Message-ID: <CAK-mJS8sE-V6qtspzzZ+bZ1eSUE_FNMt3K-5kBOG-z3NMgU_Rg@mail.gmail.com>
Subject: Test
From: Alexandru Chirila <chirila@spamexperts.com>
To: Alexandru Chirila <chirila@gapps.spamexperts.com>
Content-Type: multipart/alternative; boundary=001a11c25ff293069304f0126bfd

--001a11c25ff293069304f0126bfd
Content-Type: text/plain; charset=ISO-8859-1

This is a test.

--001a11c25ff293069304f0126bfd
Content-Type: text/html; charset=ISO-8859-1
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">
<style> This is my style.</style>
<script> This is my script.</script>
<div>This is a test.</div>
</div>

--001a11c25ff293069304f0126bfd--
"#;

    const TEXT_ATTACHMENT: &str = r#"MIME-Version: 1.0
Received: by 10.76.127.40 with HTTP; Fri, 17 Jan 2014 02:21:43 -0800 (PST)
Date: Fri, 17 Jan 2014 12:21:43 +0200
Delivered-To: chirila.s.alexandru@gmail.com
Message-ID: <CALTHOsuHFaaatiXJKU=LdDCo4NmD_h49yvG2RDsWw17D0-NXJg@mail.gmail.com>
Subject: Test
From: Alexandru Chirila <chirila.s.alexandru@gmail.com>
To: Alexandru Chirila <chirila.s.alexandru@gmail.com>
Content-Type: multipart/mixed; boundary=f46d040a62c49bb1c804f027e8cc

--f46d040a62c49bb1c804f027e8cc
Content-Type: multipart/alternative; boundary=f46d040a62c49bb1c404f027e8ca

--f46d040a62c49bb1c404f027e8ca
Content-Type: text/plain; charset=ISO-8859-1

This is a test mailing

--f46d040a62c49bb1c404f027e8ca--
--f46d040a62c49bb1c804f027e8cc
Content-Type: image/png; name="tar.png"
Content-Disposition: attachment; filename="tar.png"
Content-Transfer-Encoding: base64
X-Attachment-Id: f_hqjas5ad0

iVBORw0KGgoAAAANSUhEUgAAAskAAADlCAAAAACErzVVAAAACXBIWXMAAAsTAAALEwEAmpwYAAAD
QmCC
--f46d040a62c49bb1c804f027e8cc--"#;

    const TEXT_ATTACHMENT_W_NULL: &str = "MIME-Version: 1.0
Received: by 10.76.127.40 with HTTP; Fri, 17 Jan 2014 02:21:43 -0800 (PST)
Date: Fri, 17 Jan 2014 12:21:43 +0200
Delivered-To: chirila.s.alexandru@gmail.com
Message-ID: <CALTHOsuHFaaatiXJKU=LdDCo4NmD_h49yvG2RDsWw17D0-NXJg@mail.gmail.com>
Subject: Test
From: Alexandru Chirila <chirila.s.alexandru@gmail.com>
To: Alexandru Chirila <chirila.s.alexandru@gmail.com>
Content-Type: multipart/mixed; boundary=f46d040a62c49bb1c804f027e8cc

--f46d040a62c49bb1c804f027e8cc
Content-Type: multipart/alternative; boundary=f46d040a62c49bb1c404f027e8ca

--f46d040a62c49bb1c404f027e8ca
Content-Type: text/plain; charset=ISO-8859-1

This is a test ma\0iling
--f46d040a62c49bb1c804f027e8cc--";

    const TEXT_ATTACHMENT_W_MULTIPLE_NULLS: &str = "MIME-Version: 1.0
Received: by 10.76.127.40 with HTTP; Fri, 17 Jan 2014 02:21:43 -0800 (PST)
Date: Fri, 17 Jan 2014 12:21:43 +0200
Delivered-To: chirila.s.alexandru@gmail.com
Message-ID: <CALTHOsuHFaaatiXJKU=LdDCo4NmD_h49yvG2RDsWw17D0-NXJg@mail.gmail.com>
Subject: Test
From: Alexandru Chirila <chirila.s.alexandru@gmail.com>
To: Alexandru Chirila <chirila.s.alexandru@gmail.com>
Content-Type: multipart/mixed; boundary=f46d040a62c49bb1c804f027e8cc

--f46d040a62c49bb1c804f027e8cc
Content-Type: multipart/alternative; boundary=f46d040a62c49bb1c404f027e8ca

--f46d040a62c49bb1c404f027e8ca
Content-Type: text/plain; charset=ISO-8859-1

This is a test ma\0\0\0iling
--f46d040a62c49bb1c804f027e8cc--";

    const TEXT_ATTACHMENT_W_SUBJECT_NULL: &str = "MIME-Version: 1.0
Received: by 10.76.127.40 with HTTP; Fri, 17 Jan 2014 02:21:43 -0800 (PST)
Date: Fri, 17 Jan 2014 12:21:43 +0200
Delivered-To: chirila.s.alexandru@gmail.com
Message-ID: <CALTHOsuHFaaatiXJKU=LdDCo4NmD_h49yvG2RDsWw17D0-NXJg@mail.gmail.com>
Subject: Te\0\0\0st
From: Alexandru Chirila <chirila.s.alexandru@gmail.com>
To: Alexandru Chirila <chirila.s.alexandru@gmail.com>
Content-Type: multipart/mixed; boundary=f46d040a62c49bb1c804f027e8cc

--f46d040a62c49bb1c804f027e8cc
Content-Type: multipart/alternative; boundary=f46d040a62c49bb1c404f027e8ca

--f46d040a62c49bb1c404f027e8ca
Content-Type: text/plain; charset=ISO-8859-1

This is a test mailing
--f46d040a62c49bb1c804f027e8cc--";

    const TEXT_ATTACHMENT_W_CONTENTTYPE_NULL: &str = "MIME-Version: 1.0
Received: by 10.76.127.40 with HTTP; Fri, 17 Jan 2014 02:21:43 -0800 (PST)
Date: Fri, 17 Jan 2014 12:21:43 +0200
Delivered-To: chirila.s.alexandru@gmail.com
Message-ID: <CALTHOsuHFaaatiXJKU=LdDCo4NmD_h49yvG2RDsWw17D0-NXJg@mail.gmail.com>
Subject: Test
From: Alexandru Chirila <chirila.s.alexandru@gmail.com>
To: Alexandru Chirila <chirila.s.alexandru@gmail.com>
Content-Type: multipart/mixed; boundary=f46d040a62c49bb1c804f027e8cc

--f46d040a62c49bb1c804f027e8cc
Content-Type: multipart/alternative; boundary=f46d040a62c49bb1c404f027e8ca

--f46d040a62c49bb1c404f027e8ca
Content-Type: text/plain; charset=\"iso-8859-1\0\0\0\"

This is a test mailing
--f46d040a62c49bb1c804f027e8cc--";

    const HTML_RAW: &str = r#"<html><head><title>Email spam</title></head><body>
<p><b>Email spam</b>, also known as <b>junk email</b> 
or <b>unsolicited bulk email</b> (<i>UBE</i>), is a subset of 
<a href="/wiki/Spam_(electronic)" title="Spam (electronic)">electronic spam</a> 
involving nearly identical messages sent to numerous recipients by <a href="/wiki/Email" title="Email">
email</a>. Clicking on <a href="/wiki/Html_email#Security_vulnerabilities" title="Html email" class="mw-redirect">
links in spam email</a> may send users to <a href="/wiki/Phishing" title="Phishing">phishing</a> 
web sites or sites that are hosting <a href="/wiki/Malware" title="Malware">malware</a>.</body></html>"#;

    const HTML_RAW_STRIPED : &str = concat!("Email spam Email spam , also known as junk email or unsolicited bulk email ( UBE )," ,
                    " is a subset of electronic spam involving nearly identical messages sent to numerous recipients by email" ,
                    " . Clicking on links in spam email may send users to phishing web sites or sites that are hosting malware .");
}
