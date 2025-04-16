use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use common::{
    Core,
    auth::AccessToken,
    config::spamfilter::SpamFilterAction,
    enterprise::{
        SpamFilterLlmConfig,
        llm::{
            AiApiConfig, ChatCompletionChoice, ChatCompletionRequest, ChatCompletionResponse,
            Message,
        },
    },
};

use compact_str::{CompactString, ToCompactString};
use http_proto::{JsonResponse, ToHttpResponse};
use hyper::Method;
use mail_auth::{
    ArcOutput, DkimOutput, DkimResult, DmarcResult, IprevOutput, IprevResult, MX, SpfOutput,
    SpfResult, dkim::Signature, dmarc::Policy,
};
use mail_parser::MessageParser;
use smtp::core::{Session, SessionAddress};
use smtp_proto::{MAIL_BODY_8BITMIME, MAIL_SMTPUTF8};
use spam_filter::{
    analysis::{
        bayes::SpamFilterAnalyzeBayes, date::SpamFilterAnalyzeDate, dmarc::SpamFilterAnalyzeDmarc,
        domain::SpamFilterAnalyzeDomain, ehlo::SpamFilterAnalyzeEhlo, from::SpamFilterAnalyzeFrom,
        headers::SpamFilterAnalyzeHeaders, html::SpamFilterAnalyzeHtml, init::SpamFilterInit,
        ip::SpamFilterAnalyzeIp, llm::SpamFilterAnalyzeLlm, messageid::SpamFilterAnalyzeMid,
        mime::SpamFilterAnalyzeMime, pyzor::SpamFilterAnalyzePyzor,
        received::SpamFilterAnalyzeReceived, recipient::SpamFilterAnalyzeRecipient,
        replyto::SpamFilterAnalyzeReplyTo, reputation::SpamFilterAnalyzeReputation,
        rules::SpamFilterAnalyzeRules, score::SpamFilterAnalyzeScore,
        subject::SpamFilterAnalyzeSubject, trusted_reply::SpamFilterAnalyzeTrustedReply,
        url::SpamFilterAnalyzeUrl,
    },
    modules::html::{HtmlToken, html_to_tokens},
};
use store::Stores;
use utils::config::Config;

use crate::{
    http_server::{HttpMessage, spawn_mock_http_server},
    jmap::enterprise::EnterpriseCore,
    smtp::{DnsCache, TempDir, TestSMTP, session::TestSession},
};

const CONFIG: &str = r#"
[spam-filter.bayes.classify]
balance = "0.0"
learns = 10

[spam-filter.bayes.auto-learn.threshold]
ham = "-0.5"
spam = "6.0"

[spam-filter.score]
spam = "5.0"

[spam-filter.llm]
enable = true
model = "dummy"
prompt = "You are an AI assistant specialized in analyzing email content to detect unsolicited, commercial, or harmful messages. Format your response as follows, separated by commas: Category,Confidence,Explanation
Here's the email to analyze, please provide your analysis based on the above instructions, ensuring your response is in the specified comma-separated format."
separator = ","
categories = ["Unsolicited", "Commercial", "Harmful", "Legitimate"]
confidence = ["High", "Medium", "Low"]

[spam-filter.llm.index]
category = 0
confidence = 1
explanation = 2

[spam-filter.reputation]
enable = true

[session.rcpt]
relay = true

[storage]
data = "spamdb"
lookup = "spamdb"
blob = "spamdb"
fts = "spamdb"
directory = "spamdb"

[directory."spamdb"]
type = "internal"
store = "spamdb"

[store."spamdb"]
type = "rocksdb"
path = "{PATH}/test_antispam.db"

#[store."redis"]
#type = "redis"
#url = "redis://127.0.0.1"

[http-lookup.STWT_OPENPHISH]
enable = true
url = "https://openphish.com/feed.txt"
format = "list"
retry = "1h"
refresh = "12h"
timeout = "30s"
limits.size = 104857600
limits.entries = 900000
limits.entry-size = 512

[http-lookup.STWT_PHISHTANK]
enable = true
url = "http://data.phishtank.com/data/online-valid.csv.gz"
format = "csv"
separator = ","
index.key = 1
skip-first = true
gzipped = true
retry = "1h"
refresh = "6h"
timeout = "30s"
limits.size = 104857600
limits.entries = 900000
limits.entry-size = 512

[http-lookup.STWT_DISPOSABLE_DOMAINS]
enable = true
url = "https://disposable.github.io/disposable-email-domains/domains_mx.txt"
format = "list"
retry = "1h"
refresh = "24h"
timeout = "30s"
limits.size = 104857600
limits.entries = 900000
limits.entry-size = 512

[http-lookup.STWT_FREE_DOMAINS]
enable = true
url = "https://gist.githubusercontent.com/okutbay/5b4974b70673dfdcc21c517632c1f984/raw/993a35930a8d24a1faab1b988d19d38d92afbba4/free_email_provider_domains.txt"
format = "list"
retry = "1h"
refresh = "720h"
timeout = "30s"
limits.size = 104857600
limits.entries = 900000
limits.entry-size = 512

[enterprise.ai.dummy]
url = "https://127.0.0.1:9090/v1/chat/completions"
type = "chat"
model = "gpt-dummy"
allow-invalid-certs = true

[spam-filter.list]
"file-extensions" = { "html" = "text/html|BAD", 
                "pdf" = "application/pdf|NZ", 
                "txt" = "text/plain|message/disposition-notification|text/rfc822-headers", 
                "zip" = "AR", 
                "js" = "BAD|NZ", 
                "hta" = "BAD|NZ" }
[lookup]
"url-redirectors" = {"bit.ly", "redirect.io", "redirect.me", "redirect.org", "redirect.com", "redirect.net", "t.ly", "tinyurl.com"}
"spam-traps" = {"spamtrap@*"}
"trusted-domains" = {"stalw.art"}
"surbl-hashbl" = {"bit.ly", "drive.google.com", "lnkiy.in"}
"#;

#[tokio::test(flavor = "multi_thread")]
async fn antispam() {
    // Enable logging
    crate::enable_logging();

    // Prepare config
    let tmp_dir = TempDir::new("smtp_antispam_test", true);
    let mut config = CONFIG.replace("{PATH}", tmp_dir.temp_dir.as_path().to_str().unwrap());
    let base_path = PathBuf::from(
        std::env::var("SPAM_RULES_DIR")
            .unwrap_or_else(|_| "/Users/me/code/spam-filter".to_string()),
    );
    for section in ["rules", "lists"] {
        for entry in fs::read_dir(base_path.join(section)).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if file_name.ends_with(".toml")
                    && ((section == "rules" && file_name != "llm.toml")
                        || (section == "lists" && file_name == "scores.toml"))
                {
                    let contents = fs::read_to_string(&path).unwrap();
                    config.push_str("\n\n");
                    config.push_str(&contents);
                }
            }
        }
    }

    // Parse config
    let mut config = Config::new(&config).unwrap();
    config.resolve_all_macros().await;
    let stores = Stores::parse_all(&mut config, false).await;
    let mut core = Core::parse(&mut config, stores, Default::default())
        .await
        .enable_enterprise();
    let ai_apis = AHashMap::from_iter([(
        "dummy".to_string(),
        AiApiConfig::parse(&mut config, "dummy").unwrap().into(),
    )]);
    core.enterprise.as_mut().unwrap().spam_filter_llm =
        SpamFilterLlmConfig::parse(&mut config, &ai_apis);
    crate::AssertConfig::assert_no_errors(config);
    let server = TestSMTP::from_core(core).server;

    // Add mock DNS entries
    for (domain, ip) in [
        ("bank.com", "127.0.0.1"),
        ("apple.com", "127.0.0.1"),
        ("youtube.com", "127.0.0.1"),
        ("twitter.com", "127.0.0.3"),
        ("dkimtrusted.org.dwl.dnswl.org", "127.0.0.3"),
        ("sh-malware.com.dbl.spamhaus.org", "127.0.1.5"),
        ("surbl-abuse.com.multi.surbl.org", "127.0.0.64"),
        ("uribl-grey.com.multi.uribl.com", "127.0.0.4"),
        ("sem-uribl.com.uribl.spameatingmonkey.net", "127.0.0.2"),
        ("sem-fresh15.com.fresh15.spameatingmonkey.net", "127.0.0.2"),
        (
            "b4a64d60f67529b0b18df66ea2f292e09e43c975.ebl.msbl.org",
            "127.0.0.2",
        ),
        (
            "a95bd658068a8315dc1864d6bb79632f47692621.ebl.msbl.org",
            "127.0.1.3",
        ),
        (
            "ba76e47680ba70a0cbff8d6c92139683.hashbl.surbl.org",
            "127.0.0.16",
        ),
        (
            "0ac5b387a1c6d8461a78bbf7b172a2a1.hashbl.surbl.org",
            "127.0.0.64",
        ),
        (
            "637d6717761b5de0c84108c894bb68f2.hashbl.surbl.org",
            "127.0.0.8",
        ),
    ] {
        server.ipv4_add(
            domain,
            vec![ip.parse().unwrap()],
            Instant::now() + Duration::from_secs(100),
        );
        server.dnsbl_add(
            domain,
            vec![ip.parse().unwrap()],
            Instant::now() + Duration::from_secs(100),
        );
    }
    for mx in [
        "domain.org",
        "domain.co.uk",
        "gmail.com",
        "custom.disposable.org",
    ] {
        server.mx_add(
            mx,
            vec![MX {
                exchanges: vec!["127.0.0.1".parse().unwrap()],
                preference: 10,
            }],
            Instant::now() + Duration::from_secs(100),
        );
    }

    // Spawn mock OpenAI server
    let _tx = spawn_mock_http_server(Arc::new(|req: HttpMessage| {
        assert_eq!(req.uri.path(), "/v1/chat/completions");
        assert_eq!(req.method, Method::POST);
        let req =
            serde_json::from_slice::<ChatCompletionRequest>(req.body.as_ref().unwrap()).unwrap();
        assert_eq!(req.model, "gpt-dummy");
        let message = &req.messages[0].content;
        assert!(message.contains("You are an AI assistant specialized in analyzing email"));

        JsonResponse::new(&ChatCompletionResponse {
            created: 0,
            object: String::new(),
            id: String::new(),
            model: req.model,
            choices: vec![ChatCompletionChoice {
                index: 0,
                finish_reason: "stop".to_string(),
                message: Message {
                    role: "assistant".to_string(),
                    content: message.split_once("Subject: ").unwrap().1.to_string(),
                },
            }],
        })
        .into_http_response()
    }))
    .await;

    // Run tests
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("smtp")
        .join("antispam");
    let filter_test = std::env::var("TEST_NAME").ok();

    for test_name in [
        "combined",
        "ip",
        "helo",
        "received",
        "messageid",
        "date",
        "from",
        "subject",
        "replyto",
        "recipient",
        "headers",
        "url",
        "html",
        "mime",
        "bounce",
        "dmarc",
        "rbl",
        "replies_out",
        "replies_in",
        "spamtrap",
        "bayes_classify",
        "reputation",
        "pyzor",
        "llm",
    ] {
        if filter_test
            .as_ref()
            .is_some_and(|s| !s.eq_ignore_ascii_case(test_name))
        {
            continue;
        }
        println!("===== {test_name} =====");
        let contents = fs::read_to_string(base_path.join(format!("{test_name}.test"))).unwrap();
        let mut lines = contents.lines();
        let mut has_more = true;

        while has_more {
            let mut message = String::new();
            let mut in_params = true;

            // Build session
            let mut session = Session::test(server.clone());
            let mut arc_result = None;
            let mut dkim_result = None;
            let mut dkim_signatures = vec![];
            let mut dmarc_result = None;
            let mut dmarc_policy = None;
            let mut expected_tags: AHashSet<CompactString> = AHashSet::new();
            let mut expect_headers = String::new();
            let mut score_set = 0.0;
            let mut score_final = 0.0;
            let mut body_params = 0;
            let mut is_tls = false;

            for line in lines.by_ref() {
                if in_params {
                    if line.is_empty() {
                        in_params = false;
                        continue;
                    }
                    let (param, value) = line.split_once(' ').unwrap();
                    let value = value.trim();
                    match param {
                        "remote_ip" => {
                            session.data.remote_ip_str = value.to_string();
                            session.data.remote_ip = value.parse().unwrap();
                        }
                        "helo_domain" => {
                            session.data.helo_domain = value.to_string();
                        }
                        "authenticated_as" => {
                            session.data.authenticated_as = Some(Arc::new(AccessToken {
                                name: value.to_string(),
                                ..Default::default()
                            }));
                        }
                        "spf.result" | "spf_ehlo.result" => {
                            session.data.spf_mail_from =
                                Some(SpfOutput::default().with_result(SpfResult::from_str(value)));
                        }
                        "iprev.result" => {
                            session
                                .data
                                .iprev
                                .get_or_insert(IprevOutput {
                                    result: IprevResult::None,
                                    ptr: None,
                                })
                                .result = IprevResult::from_str(value);
                        }
                        "dkim.result" => {
                            dkim_result = match DkimResult::from_str(value) {
                                DkimResult::Pass => DkimOutput::pass(),
                                DkimResult::Neutral(error) => DkimOutput::neutral(error),
                                DkimResult::Fail(error) => DkimOutput::fail(error),
                                DkimResult::PermError(error) => DkimOutput::perm_err(error),
                                DkimResult::TempError(error) => DkimOutput::temp_err(error),
                                DkimResult::None => unreachable!(),
                            }
                            .into();
                        }
                        "arc.result" => {
                            arc_result = ArcOutput::default()
                                .with_result(DkimResult::from_str(value))
                                .into();
                        }
                        "dkim.domains" => {
                            dkim_signatures = value
                                .split_ascii_whitespace()
                                .map(|s| Signature {
                                    d: s.to_lowercase(),
                                    ..Default::default()
                                })
                                .collect();
                        }
                        "envelope_from" => {
                            session.data.mail_from = Some(SessionAddress::new(value.to_string()));
                        }
                        "envelope_to" => {
                            session
                                .data
                                .rcpt_to
                                .push(SessionAddress::new(value.to_string()));
                        }
                        "iprev.ptr" => {
                            session
                                .data
                                .iprev
                                .get_or_insert(IprevOutput {
                                    result: IprevResult::None,
                                    ptr: None,
                                })
                                .ptr = Some(Arc::new(vec![value.to_string()]));
                        }
                        "dmarc.result" => {
                            dmarc_result = DmarcResult::from_str(value).into();
                        }
                        "dmarc.policy" => {
                            dmarc_policy = Policy::from_str(value).into();
                        }
                        "expect" => {
                            expected_tags.extend(
                                value
                                    .split_ascii_whitespace()
                                    .map(|v| v.to_uppercase().into()),
                            );
                        }
                        "expect_header" => {
                            let value = value.trim();
                            if !value.is_empty() {
                                if !expect_headers.is_empty() {
                                    expect_headers.push(' ');
                                }
                                expect_headers.push_str(value);
                            }
                        }
                        "score" => {
                            score_set = value.parse::<f64>().unwrap();
                        }
                        "final_score" => {
                            score_final = value.parse::<f64>().unwrap();
                        }
                        "param.smtputf8" => {
                            body_params |= MAIL_SMTPUTF8;
                        }
                        "param.8bitmime" => {
                            body_params |= MAIL_BODY_8BITMIME;
                        }
                        "tls.version" => {
                            is_tls = true;
                        }
                        _ => panic!("Invalid parameter {param:?}"),
                    }
                } else {
                    has_more = line.trim().eq_ignore_ascii_case("<!-- NEXT TEST -->");
                    if !has_more {
                        message.push_str(line);
                        message.push_str("\r\n");
                    } else {
                        break;
                    }
                }
            }

            if message.is_empty() {
                panic!("No message found");
            }

            if body_params != 0 {
                session
                    .data
                    .mail_from
                    .get_or_insert_with(|| SessionAddress::new("".to_string()))
                    .flags = body_params;
            }

            // Build input
            let mut dkim_domains = vec![];
            if let Some(dkim_result) = dkim_result {
                if dkim_signatures.is_empty() {
                    dkim_signatures.push(Signature {
                        d: "unknown.org".to_string(),
                        ..Default::default()
                    });
                }

                for signature in &dkim_signatures {
                    dkim_domains.push(dkim_result.clone().with_signature(signature));
                }
            }
            let parsed_message = MessageParser::new().parse(&message).unwrap();

            // Combined tests
            if test_name == "combined" {
                match session
                    .spam_classify(
                        &parsed_message,
                        &dkim_domains,
                        arc_result.as_ref(),
                        dmarc_result.as_ref(),
                        dmarc_policy.as_ref(),
                    )
                    .await
                {
                    SpamFilterAction::Allow(header) => {
                        let mut last_ch = 'x';
                        let mut result = String::with_capacity(header.len());
                        for ch in header.chars() {
                            if !ch.is_whitespace() {
                                if last_ch.is_whitespace() {
                                    result.push(' ');
                                }
                                result.push(ch);
                            }
                            last_ch = ch;
                        }
                        assert_eq!(result, expect_headers);
                    }
                    other => panic!("Unexpected action {other:?}"),
                }
                continue;
            }

            // Initialize filter
            let mut spam_input = session.build_spam_input(
                &parsed_message,
                &dkim_domains,
                arc_result.as_ref(),
                dmarc_result.as_ref(),
                dmarc_policy.as_ref(),
            );
            spam_input.is_tls = is_tls;
            let mut spam_ctx = server.spam_filter_init(spam_input);
            match test_name {
                "html" => {
                    server.spam_filter_analyze_html(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                }
                "subject" => {
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| t.starts_with("X_HDR_"));
                    server.spam_filter_analyze_subject(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "received" => {
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| t.starts_with("X_HDR_"));
                    server.spam_filter_analyze_received(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "messageid" => {
                    server.spam_filter_analyze_message_id(&mut spam_ctx).await;
                }
                "date" => {
                    server.spam_filter_analyze_date(&mut spam_ctx).await;
                }
                "from" => {
                    server.spam_filter_analyze_from(&mut spam_ctx).await;
                    server.spam_filter_analyze_domain(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                }
                "replyto" => {
                    server.spam_filter_analyze_reply_to(&mut spam_ctx).await;
                    server.spam_filter_analyze_domain(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                }
                "recipient" => {
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| t.starts_with("X_HDR_"));
                    server.spam_filter_analyze_recipient(&mut spam_ctx).await;
                    server.spam_filter_analyze_domain(&mut spam_ctx).await;
                    server.spam_filter_analyze_subject(&mut spam_ctx).await;
                    server.spam_filter_analyze_url(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "mime" => {
                    server.spam_filter_analyze_mime(&mut spam_ctx).await;
                }
                "headers" => {
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "url" => {
                    server.spam_filter_analyze_url(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                }
                "dmarc" => {
                    server.spam_filter_analyze_dmarc(&mut spam_ctx).await;
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "ip" => {
                    server.spam_filter_analyze_ip(&mut spam_ctx).await;
                }
                "helo" => {
                    server.spam_filter_analyze_ehlo(&mut spam_ctx).await;
                }
                "bounce" => {
                    server.spam_filter_analyze_mime(&mut spam_ctx).await;
                    server.spam_filter_analyze_headers(&mut spam_ctx).await;
                    server.spam_filter_analyze_rules(&mut spam_ctx).await;
                    spam_ctx.result.tags.retain(|t| !t.starts_with("X_HDR_"));
                }
                "rbl" => {
                    server.spam_filter_analyze_url(&mut spam_ctx).await;
                    server.spam_filter_analyze_ip(&mut spam_ctx).await;
                    server.spam_filter_analyze_domain(&mut spam_ctx).await;
                }
                "replies_out" => {
                    server.spam_filter_analyze_reply_out(&mut spam_ctx).await;
                }
                "replies_in" => {
                    server.spam_filter_analyze_reply_in(&mut spam_ctx).await;
                }
                "spamtrap" => {
                    server.spam_filter_analyze_spam_trap(&mut spam_ctx).await;
                    server.spam_filter_finalize(&mut spam_ctx).await;
                }
                "bayes_classify" => {
                    server
                        .spam_filter_analyze_bayes_classify(&mut spam_ctx)
                        .await;
                }
                "reputation" => {
                    spam_ctx.result.score = score_set;
                    server.spam_filter_analyze_reputation(&mut spam_ctx).await;
                    assert_eq!(spam_ctx.result.score, score_final);
                }
                "pyzor" => {
                    server.spam_filter_analyze_pyzor(&mut spam_ctx).await;
                }
                "llm" => {
                    server.spam_filter_analyze_llm(&mut spam_ctx).await;
                }
                _ => panic!("Invalid test {test_name:?}"),
            }

            // Compare tags
            if spam_ctx.result.tags != expected_tags {
                for tag in &spam_ctx.result.tags {
                    if !expected_tags.contains(tag) {
                        println!("Unexpected tag: {tag:?}");
                    }
                }

                for tag in &expected_tags {
                    if !spam_ctx.result.tags.contains(tag) {
                        println!("Missing tag: {tag:?}");
                    }
                }

                panic!("Tags mismatch, expected {expected_tags:?}");
            } else {
                println!("Tags matched: {expected_tags:?}");
            }
        }
    }
}

trait ParseConfigValue: Sized {
    fn from_str(value: &str) -> Self;
}

impl ParseConfigValue for SpfResult {
    fn from_str(value: &str) -> Self {
        match value {
            "pass" => SpfResult::Pass,
            "fail" => SpfResult::Fail,
            "softfail" => SpfResult::SoftFail,
            "neutral" => SpfResult::Neutral,
            "none" => SpfResult::None,
            "temperror" => SpfResult::TempError,
            "permerror" => SpfResult::PermError,
            _ => panic!("Invalid SPF result"),
        }
    }
}

impl ParseConfigValue for IprevResult {
    fn from_str(value: &str) -> Self {
        match value {
            "pass" => IprevResult::Pass,
            "fail" => IprevResult::Fail(mail_auth::Error::NotAligned),
            "temperror" => IprevResult::TempError(mail_auth::Error::NotAligned),
            "permerror" => IprevResult::PermError(mail_auth::Error::NotAligned),
            "none" => IprevResult::None,
            _ => panic!("Invalid IPREV result"),
        }
    }
}

impl ParseConfigValue for DkimResult {
    fn from_str(value: &str) -> Self {
        match value {
            "pass" => DkimResult::Pass,
            "none" => DkimResult::None,
            "neutral" => DkimResult::Neutral(mail_auth::Error::NotAligned),
            "fail" => DkimResult::Fail(mail_auth::Error::NotAligned),
            "permerror" => DkimResult::PermError(mail_auth::Error::NotAligned),
            "temperror" => DkimResult::TempError(mail_auth::Error::NotAligned),
            _ => panic!("Invalid DKIM result"),
        }
    }
}

impl ParseConfigValue for DmarcResult {
    fn from_str(value: &str) -> Self {
        match value {
            "pass" => DmarcResult::Pass,
            "fail" => DmarcResult::Fail(mail_auth::Error::NotAligned),
            "temperror" => DmarcResult::TempError(mail_auth::Error::NotAligned),
            "permerror" => DmarcResult::PermError(mail_auth::Error::NotAligned),
            "none" => DmarcResult::None,
            _ => panic!("Invalid DMARC result"),
        }
    }
}

impl ParseConfigValue for Policy {
    fn from_str(value: &str) -> Self {
        match value {
            "reject" => Policy::Reject,
            "quarantine" => Policy::Quarantine,
            "none" => Policy::None,
            _ => panic!("Invalid DMARC policy"),
        }
    }
}

#[test]
fn html_tokens() {
    for (input, expected) in [
        (
            concat!("<html>hello<br/>world<br/></html>"),
            vec![
                HtmlToken::StartTag {
                    name: 1819112552,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "hello".to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 29282,
                    attributes: vec![],
                    is_self_closing: true,
                },
                HtmlToken::Text {
                    text: "world".to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 29282,
                    attributes: vec![],
                    is_self_closing: true,
                },
                HtmlToken::EndTag { name: 1819112552 },
            ],
        ),
        (
            concat!("<html>using &lt;><br/></html>"),
            vec![
                HtmlToken::StartTag {
                    name: 1819112552,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "using <>".to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 29282,
                    attributes: vec![],
                    is_self_closing: true,
                },
                HtmlToken::EndTag { name: 1819112552 },
            ],
        ),
        (
            concat!("test <not br/>tag<br />"),
            vec![
                HtmlToken::Text {
                    text: "test".to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 7630702,
                    attributes: vec![(29282, None)],
                    is_self_closing: true,
                },
                HtmlToken::Text {
                    text: " tag".to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 29282,
                    attributes: vec![],
                    is_self_closing: true,
                },
            ],
        ),
        (
            concat!("<>< ><tag\n/>>hello    world< br \n />"),
            vec![
                HtmlToken::StartTag {
                    name: 6775156,
                    attributes: vec![],
                    is_self_closing: true,
                },
                HtmlToken::Text {
                    text: ">hello world".to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 29282,
                    attributes: vec![],
                    is_self_closing: true,
                },
            ],
        ),
        (
            concat!(
                "<head><title>ignore head</title><not hea",
                "d>xyz</not head></head><h1>&lt;body&gt;<",
                "/h1>"
            ),
            vec![
                HtmlToken::StartTag {
                    name: 1684104552,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::StartTag {
                    name: 435611265396,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "ignore head".to_compact_string(),
                },
                HtmlToken::EndTag { name: 435611265396 },
                HtmlToken::StartTag {
                    name: 7630702,
                    attributes: vec![(1684104552, None)],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "xyz".to_compact_string(),
                },
                HtmlToken::EndTag { name: 7630702 },
                HtmlToken::EndTag { name: 1684104552 },
                HtmlToken::StartTag {
                    name: 12648,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "<body>".to_compact_string(),
                },
                HtmlToken::EndTag { name: 12648 },
            ],
        ),
        (
            concat!(
                "<p>what is &heartsuit;?</p><p>&#x000DF;&",
                "Abreve;&#914;&gamma; don&apos;t hurt me.",
                "</p>"
            ),
            vec![
                HtmlToken::StartTag {
                    name: 112,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "what is ♥?".to_compact_string(),
                },
                HtmlToken::EndTag { name: 112 },
                HtmlToken::StartTag {
                    name: 112,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "ßĂΒγ don't hurt me.".to_compact_string(),
                },
                HtmlToken::EndTag { name: 112 },
            ],
        ),
        (
            concat!(
                "<!--[if mso]><style type=\"text/css\">body",
                ", table, td, a, p, span, ul, li {font-fa",
                "mily: Arial, sans-serif!important;}</sty",
                "le><![endif]-->this is <!-- <> < < < < i",
                "gnore  > -> here -->the actual<!--> text"
            ),
            vec![
                HtmlToken::Comment {
                    text: concat!(
                        "!--[if mso]><style type=\"text/css\">body, ",
                        "table, td, a, p, span, ul, li {font-family: ",
                        "Arial, sans-serif!important;}</style><![endif]--"
                    )
                    .to_compact_string(),
                },
                HtmlToken::Text {
                    text: "this is".to_compact_string(),
                },
                HtmlToken::Comment {
                    text: "!-- <> < < < < ignore  > -> here --".to_compact_string(),
                },
                HtmlToken::Text {
                    text: " the actual".to_compact_string(),
                },
                HtmlToken::Comment {
                    text: "!--".to_compact_string(),
                },
                HtmlToken::Text {
                    text: " text".to_compact_string(),
                },
            ],
        ),
        (
            concat!(
                "   < p >  hello < / p > < p > world < / ",
                "p >   !!! < br > "
            ),
            vec![
                HtmlToken::StartTag {
                    name: 112,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "hello".to_compact_string(),
                },
                HtmlToken::EndTag { name: 112 },
                HtmlToken::StartTag {
                    name: 112,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: " world".to_compact_string(),
                },
                HtmlToken::EndTag { name: 112 },
                HtmlToken::Text {
                    text: " !!!".to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 29282,
                    attributes: vec![],
                    is_self_closing: false,
                },
            ],
        ),
        (
            concat!(" <p>please unsubscribe <a href=#>here</a", ">.</p> "),
            vec![
                HtmlToken::StartTag {
                    name: 112,
                    attributes: vec![],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "please unsubscribe".to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("#".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: " here".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::Text {
                    text: ".".to_compact_string(),
                },
                HtmlToken::EndTag { name: 112 },
            ],
        ),
        (
            concat!(
                "<a href=\"a\">text</a><a href =\"b\">text</a",
                "><a href= \"c\">text</a><a href = \"d\">text",
                "</a><  a href = \"e\" >text</a><a hrefer =",
                " \"ignore\" >text</a>< anchor href = \"x\">t",
                "ext</a>"
            ),
            vec![
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("a".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("b".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("c".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("d".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("e".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(125779835187816, Some("ignore".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 125822818283105,
                    attributes: vec![(1717924456, Some("x".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
            ],
        ),
        (
            concat!(
                "<a href=a>text</a><a href =b>text</a><a ",
                "href= c>text</a><a href = d>text</a>< a ",
                "href  =  e >text</a><a hrefer = ignore>t",
                "ext</a><anchor href=x>text</a>"
            ),
            vec![
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("a".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("b".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("c".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("d".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("e".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(125779835187816, Some("ignore".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 125822818283105,
                    attributes: vec![(1717924456, Some("x".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
            ],
        ),
        (
            concat!(
                "<!-- <a href=a>text</a><a href =b>text</",
                "a><a href= c>--text</a>--><a href = \"hel",
                "lo world\">text</a>< a href  =  test igno",
                "re>text</a>< a href  =  fudge href ignor",
                "e>text</a><a href=foobar> a href = \"unkn",
                "own\" </a>"
            ),
            vec![
                HtmlToken::Comment {
                    text: "!-- <a href=a>text</a><a href =b>text</a><a href= c>--text</a>--"
                        .to_compact_string(),
                },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("hello world".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![
                        (1717924456, Some("test".to_compact_string())),
                        (111542170183529, None),
                    ],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![
                        (1717924456, Some("fudge".to_compact_string())),
                        (1717924456, None),
                        (111542170183529, None),
                    ],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "text".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(1717924456, Some("foobar".to_compact_string()))],
                    is_self_closing: false,
                },
                HtmlToken::Text {
                    text: "a href = \"unknown\"".to_compact_string(),
                },
                HtmlToken::EndTag { name: 97 },
            ],
        ),
    ] {
        assert_eq!(expected, html_to_tokens(input), "failed for {input:?}");
    }
}
