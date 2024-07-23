use std::{
    borrow::Cow,
    collections::HashMap,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use common::{
    scripts::{
        functions::html::{get_attribute, html_attr_tokens, html_img_area, html_to_tokens},
        ScriptModification,
    },
    Core,
};
use mail_auth::{dmarc::Policy, DkimResult, DmarcResult, IprevResult, SpfResult, MX};
use sieve::runtime::Variable;
use smtp::{
    core::{Inner, Session, SessionAddress},
    inbound::AuthResult,
    scripts::ScriptResult,
};
use store::Stores;
use utils::config::Config;

use crate::smtp::{build_smtp, session::TestSession, TempDir};

const CONFIG: &str = r#"
[spam.header]
is-spam = "X-Spam-Status: Yes"

[lookup.spam-config]
add-spam = true
add-spam-result = true
learn-enable = true
#learn-balance = "0.9"
learn-balance = "0.0"
learn-ham-replies = true
learn-ham-threshold = "-0.5"
learn-spam-threshold = "6.0"
threshold-spam = "5.0"
threshold-discard = 0
threshold-reject = 0
directory = ""
lookup = ""

[session.rcpt]
relay = true

[sieve.trusted]
from-name = "'Sieve Daemon'"
from-addr = "'sieve@foobar.org'"
return-path = ""
hostname = "mx.foobar.org"
no-capability-check = true

[sieve.trusted.limits]
redirects = 3
out-messages = 5
received-headers = 50
cpu = 500000
nested-includes = 5
duplicate-expiry = "7d"

[storage]
data = "spamdb"
lookup = "spamdb"
blob = "spamdb"
fts = "spamdb"

[store."spamdb"]
type = "sqlite"
path = "{PATH}/test_antispam.db"

#[store."redis"]
#type = "redis"
#url = "redis://127.0.0.1"

[lookup]
"spam-free" = {"gmail.com", "googlemail.com", "yahoomail.com", "*.freemail.org"}
"spam-disposable" = {"guerrillamail.com", "*.disposable.org"}
"spam-redirect" = {"bit.ly", "redirect.io", "redirect.me", "redirect.org", "redirect.com", "redirect.net", "t.ly", "tinyurl.com"}
"spam-dmarc" = {"dmarc-allow.org"}
"spam-spdk" = {"spf-dkim-allow.org"}
"spam-mime" = { "html" = "text/html|BAD", 
                "pdf" = "application/pdf|NZ", 
                "txt" = "text/plain|message/disposition-notification|text/rfc822-headers", 
                "zip" = "AR", 
                "js" = "BAD|NZ", 
                "hta" = "BAD|NZ" }
"spam-trap" = {"spamtrap@*"}
"spam-allow" = {"stalw.art"}

[resolver]
public-suffix = "file://{LIST_PATH}/public-suffix.dat"

[sieve.trusted.scripts]
"#;

#[tokio::test(flavor = "multi_thread")]
async fn antispam() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(
                tracing_subscriber::EnvFilter::builder()
                    .parse(
                        "smtp=debug,imap=debug,jmap=debug,store=debug,utils=debug,directory=debug,common=trace",
                    )
                    .unwrap(),
            )
            .finish(),
    )
    .unwrap();*/

    // Prepare config
    let tests = [
        "html",
        "subject",
        "bounce",
        "received",
        "messageid",
        "date",
        "from",
        "replyto",
        "recipient",
        "mime",
        "headers",
        "url",
        "dmarc",
        "ip",
        "helo",
        "rbl",
        "replies_out",
        "replies_in",
        "spamtrap",
        "bayes_classify",
        "reputation",
        "pyzor",
    ];
    let tmp_dir = TempDir::new("smtp_antispam_test", true);
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
        .join("resources")
        .join("config")
        .join("spamfilter");
    let mut config = CONFIG
        .replace("{PATH}", tmp_dir.temp_dir.as_path().to_str().unwrap())
        .replace(
            "{LIST_PATH}",
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("smtp")
                .join("lists")
                .to_str()
                .unwrap(),
        );
    let scores = fs::read_to_string(base_path.join("maps").join("scores.map")).unwrap();
    let base_path = base_path.join("scripts");
    let script_config = fs::read_to_string(base_path.join("config.sieve")).unwrap();
    let script_prelude = fs::read_to_string(base_path.join("prelude.sieve")).unwrap();
    let mut all_scripts = script_config.clone() + "\n" + script_prelude.as_str();
    for test_name in tests {
        let mut script = fs::read_to_string(base_path.join(format!("{test_name}.sieve"))).unwrap();
        if !["reputation", "replies_out", "pyzor"].contains(&test_name) {
            all_scripts = all_scripts + "\n" + script.as_str();
        }

        if test_name == "reputation" {
            script = "let \"score\" \"env.score\";\n\n".to_string()
                + script.as_str()
                + concat!(
                    "\n\nif eval \"score != env.final_score\" ",
                    "{let \"t.INVALID_SCORE\" \"score\";}\n"
                );
        } else if test_name == "bayes_classify" {
            script = script.replace("200", "10");
        }

        config.push_str(&format!(
            "{test_name}.contents = '''{script_config}\n{script_prelude}\n{script}\n'''\n"
        ));
    }
    for test_name in ["composites", "scores", "epilogue"] {
        all_scripts = all_scripts
            + "\n"
            + fs::read_to_string(base_path.join(format!("{test_name}.sieve")))
                .unwrap()
                .as_str();
    }

    config.push_str(&format!(
        "combined.contents = '''{all_scripts}\n'''\n[lookup]\n"
    ));
    config.push_str(&scores);

    // Parse config
    let mut config = Config::new(&config).unwrap();
    config.resolve_all_macros().await;
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;
    //config.assert_no_errors();

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
            "94c57fe69a113e875f772bdea55bf2c3.hashbl.surbl.org",
            "127.0.0.16",
        ),
        (
            "64aca53deb83db2ba30a59604ada2d80.hashbl.surbl.org",
            "127.0.0.64",
        ),
        (
            "02159eed92622b2fb8c83c659f269007.hashbl.surbl.org",
            "127.0.0.8",
        ),
    ] {
        core.smtp.resolvers.dns.ipv4_add(
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
        core.smtp.resolvers.dns.mx_add(
            mx,
            vec![MX {
                exchanges: vec!["127.0.0.1".parse().unwrap()],
                preference: 10,
            }],
            Instant::now() + Duration::from_secs(100),
        );
    }

    let core = build_smtp(core, Inner::default());

    // Run tests
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("smtp")
        .join("antispam");
    for &test_name in tests.iter().chain(&["combined"]) {
        /*if test_name != "combined" {
            continue;
        }*/
        println!("===== {test_name} =====");
        let script = core.core.sieve.scripts.get(test_name).cloned().unwrap();

        let contents = fs::read_to_string(base_path.join(format!("{test_name}.test"))).unwrap();
        let mut lines = contents.lines();
        let mut has_more = true;

        while has_more {
            let mut message = String::new();
            let mut in_params = true;
            let mut variables: HashMap<String, Variable> = HashMap::new();
            let mut expected_variables = AHashMap::new();
            let mut expected_headers = AHashMap::new();

            // Build session
            let mut session = Session::test(core.clone());
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
                            session.data.authenticated_as = value.to_string();
                        }
                        "spf.result" | "spf_ehlo.result" => {
                            variables.insert(
                                param.to_string(),
                                SpfResult::from_str(value).as_str().to_string().into(),
                            );
                        }
                        "iprev.result" => {
                            variables.insert(
                                param.to_string(),
                                IprevResult::from_str(value).as_str().to_string().into(),
                            );
                        }
                        "dkim.result" | "arc.result" => {
                            variables.insert(
                                param.to_string(),
                                DkimResult::from_str(value).as_str().to_string().into(),
                            );
                        }
                        "dkim.domains" => {
                            variables.insert(
                                param.to_string(),
                                value
                                    .split_ascii_whitespace()
                                    .map(|s| Variable::from(s.to_string()))
                                    .collect::<Vec<_>>()
                                    .into(),
                            );
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
                            variables.insert(param.to_string(), value.to_string().into());
                        }
                        "dmarc.result" => {
                            variables.insert(
                                param.to_string(),
                                DmarcResult::from_str(value).as_str().to_string().into(),
                            );
                        }
                        "dmarc.policy" => {
                            variables.insert(
                                param.to_string(),
                                Policy::from_str(value).as_str().to_string().into(),
                            );
                        }
                        "expect" => {
                            expected_variables.extend(value.split_ascii_whitespace().map(|v| {
                                v.split_once('=')
                                    .map(|(k, v)| {
                                        (
                                            k.to_lowercase(),
                                            if v.contains('.') {
                                                Variable::Float(v.parse().unwrap())
                                            } else {
                                                Variable::Integer(v.parse().unwrap())
                                            },
                                        )
                                    })
                                    .unwrap_or((v.to_lowercase(), Variable::Integer(1)))
                            }));
                        }
                        "expect_header" => {
                            if let Some((header, value)) = value.split_once(' ') {
                                expected_headers
                                    .insert(header.to_string(), value.trim().to_string());
                            } else {
                                expected_headers.insert(value.to_string(), String::new());
                            }
                        }
                        "score" | "final_score" => {
                            variables
                                .insert(param.to_string(), value.parse::<f64>().unwrap().into());
                        }
                        _ if param.starts_with("param.") | param.starts_with("tls.") => {
                            variables.insert(param.to_string(), value.to_string().into());
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

            // Build script params
            let mut expected = expected_variables.keys().collect::<Vec<_>>();
            expected.sort_unstable_by(|a, b| b.cmp(a));
            println!("Testing tags {:?}", expected);
            let mut params = session
                .build_script_parameters("data")
                .with_expected_variables(expected_variables)
                .with_message(message.as_bytes());
            for (name, value) in variables {
                params = params.set_variable(name, value);
            }

            // Run script
            let core_ = core.clone();
            let script = script.clone();
            match core_.run_script(script, params, 0).await {
                ScriptResult::Accept { modifications } => {
                    if modifications.len() != expected_headers.len() {
                        panic!(
                            "Expected {:?} headers, got {:?}",
                            expected_headers, modifications
                        );
                    }
                    for modification in modifications {
                        if let ScriptModification::AddHeader { name, value } = modification {
                            if let Some(expected_value) = expected_headers.remove(name.as_str()) {
                                if !expected_value.is_empty()
                                    && !value.starts_with(expected_value.as_str())
                                {
                                    panic!(
                                        "Expected header {:?} to be {:?}, got {:?}",
                                        name, expected_value, value
                                    );
                                }
                            } else {
                                panic!("Unexpected header {:?}", name);
                            }
                        } else {
                            panic!("Unexpected modification {:?}", modification);
                        }
                    }
                }
                ScriptResult::Reject(message) => panic!("{}", message),
                ScriptResult::Replace {
                    message,
                    modifications,
                } => println!(
                    "Replace: {} with modifications {:?}",
                    String::from_utf8_lossy(&message),
                    modifications
                ),
                ScriptResult::Discard => println!("Discard"),
            }
        }
    }
}

#[test]
fn html_tokens() {
    for (input, expected) in [
        (
            "<html>hello<br/>world<br/></html>",
            vec![
                Variable::from("<html".to_string()),
                Variable::from("_hello".to_string()),
                Variable::from("<br/".to_string()),
                Variable::from("_world".to_string()),
                Variable::from("<br/".to_string()),
                Variable::from("</html".to_string()),
            ],
        ),
        (
            "<html>using &lt;><br/></html>",
            vec![
                Variable::from("<html".to_string()),
                Variable::from("_using <>".to_string()),
                Variable::from("<br/".to_string()),
                Variable::from("</html".to_string()),
            ],
        ),
        (
            "test <not br/>tag<br />",
            vec![
                Variable::from("_test".to_string()),
                Variable::from("<not br/".to_string()),
                Variable::from("_ tag".to_string()),
                Variable::from("<br /".to_string()),
            ],
        ),
        (
            "<>< ><tag\n/>>hello    world< br \n />",
            vec![
                Variable::from("<".to_string()),
                Variable::from("<".to_string()),
                Variable::from("<tag /".to_string()),
                Variable::from("_>hello world".to_string()),
                Variable::from("<br /".to_string()),
            ],
        ),
        (
            concat!(
                "<head><title>ignore head</title><not head>xyz</not head></head>",
                "<h1>&lt;body&gt;</h1>"
            ),
            vec![
                Variable::from("<head".to_string()),
                Variable::from("<title".to_string()),
                Variable::from("_ignore head".to_string()),
                Variable::from("</title".to_string()),
                Variable::from("<not head".to_string()),
                Variable::from("_xyz".to_string()),
                Variable::from("</not head".to_string()),
                Variable::from("</head".to_string()),
                Variable::from("<h1".to_string()),
                Variable::from("_<body>".to_string()),
                Variable::from("</h1".to_string()),
            ],
        ),
        (
            concat!(
                "<p>what is &heartsuit;?</p><p>&#x000DF;&Abreve;&#914;&gamma; ",
                "don&apos;t hurt me.</p>"
            ),
            vec![
                Variable::from("<p".to_string()),
                Variable::from("_what is ♥?".to_string()),
                Variable::from("</p".to_string()),
                Variable::from("<p".to_string()),
                Variable::from("_ßĂΒγ don't hurt me.".to_string()),
                Variable::from("</p".to_string()),
            ],
        ),
        (
            concat!(
                "<!--[if mso]><style type=\"text/css\">body, table, td, a, p, ",
                "span, ul, li {font-family: Arial, sans-serif!important;}</style><![endif]-->",
                "this is <!-- <> < < < < ignore  > -> here -->the actual<!--> text"
            ),
            vec![
                Variable::from(
                    concat!(
                        "<!--[if mso]><style type=\"text/css\">body, table, ",
                        "td, a, p, span, ul, li {font-family: Arial, sans-serif!",
                        "important;}</style><![endif]--"
                    )
                    .to_string(),
                ),
                Variable::from("_this is".to_string()),
                Variable::from("<!-- <> < < < < ignore  > -> here --".to_string()),
                Variable::from("_ the actual".to_string()),
                Variable::from("<!--".to_string()),
                Variable::from("_ text".to_string()),
            ],
        ),
        (
            "   < p >  hello < / p > < p > world < / p >   !!! < br > ",
            vec![
                Variable::from("<p ".to_string()),
                Variable::from("_hello".to_string()),
                Variable::from("</p ".to_string()),
                Variable::from("<p ".to_string()),
                Variable::from("_ world".to_string()),
                Variable::from("</p ".to_string()),
                Variable::from("_ !!!".to_string()),
                Variable::from("<br ".to_string()),
            ],
        ),
        (
            " <p>please unsubscribe <a href=#>here</a>.</p> ",
            vec![
                Variable::from("<p".to_string()),
                Variable::from("_please unsubscribe".to_string()),
                Variable::from("<a href=#".to_string()),
                Variable::from("_ here".to_string()),
                Variable::from("</a".to_string()),
                Variable::from("_.".to_string()),
                Variable::from("</p".to_string()),
            ],
        ),
    ] {
        assert_eq!(html_to_tokens(input), expected, "Failed for '{:?}'", input);
    }

    for (input, expected) in [
        (
            concat!(
                "<a href=\"a\">text</a>",
                "<a href =\"b\">text</a>",
                "<a href= \"c\">text</a>",
                "<a href = \"d\">text</a>",
                "<  a href = \"e\" >text</a>",
                "<a hrefer = \"ignore\" >text</a>",
                "< anchor href = \"x\">text</a>",
            ),
            vec![
                Variable::from("a".to_string()),
                Variable::from("b".to_string()),
                Variable::from("c".to_string()),
                Variable::from("d".to_string()),
                Variable::from("e".to_string()),
            ],
        ),
        (
            concat!(
                "<a href=a>text</a>",
                "<a href =b>text</a>",
                "<a href= c>text</a>",
                "<a href = d>text</a>",
                "< a href  =  e >text</a>",
                "<a hrefer = ignore>text</a>",
                "<anchor href=x>text</a>",
            ),
            vec![
                Variable::from("a".to_string()),
                Variable::from("b".to_string()),
                Variable::from("c".to_string()),
                Variable::from("d".to_string()),
                Variable::from("e".to_string()),
            ],
        ),
        (
            concat!(
                "<!-- <a href=a>text</a>",
                "<a href =b>text</a>",
                "<a href= c>--text</a>-->",
                "<a href = \"hello world\">text</a>",
                "< a href  =  test ignore>text</a>",
                "< a href  =  fudge href ignore>text</a>",
                "<a href=foobar> a href = \"unknown\" </a>",
            ),
            vec![
                Variable::from("hello world".to_string()),
                Variable::from("test".to_string()),
                Variable::from("fudge".to_string()),
                Variable::from("foobar".to_string()),
            ],
        ),
    ] {
        assert_eq!(
            html_attr_tokens(input, "a", vec![Cow::from("href")]),
            expected,
            "Failed for '{:?}'",
            input
        );
    }

    for (tag, attr_name, expected) in [
        ("<img width=200 height=400", "width", "200"),
        ("<img width=200 height=400", "height", "400"),
        ("<img width = 200 height = 400", "width", "200"),
        ("<img width = 200 height = 400", "height", "400"),
        ("<img width =200 height =400", "width", "200"),
        ("<img width =200 height =400", "height", "400"),
        ("<img width= 200 height= 400", "width", "200"),
        ("<img width= 200 height= 400", "height", "400"),
        ("<img width=\"200\" height=\"400\"", "width", "200"),
        ("<img width=\"200\" height=\"400\"", "height", "400"),
        ("<img width = \"200\" height = \"400\"", "width", "200"),
        ("<img width = \"200\" height = \"400\"", "height", "400"),
        (
            "<img width=\" 200 % \" height=\" 400 % \"",
            "width",
            " 200 % ",
        ),
        (
            "<img width=\" 200 % \" height=\" 400 % \"",
            "height",
            " 400 % ",
        ),
    ] {
        assert_eq!(
            get_attribute(tag, attr_name).unwrap_or_default(),
            expected,
            "failed for {tag:?}, {attr_name:?}"
        );
    }

    assert_eq!(
        html_img_area(&html_to_tokens(concat!(
            "<img width=200 height=400 />",
            "20",
            "30",
            "<img width=10% height=\" 20% \"/>",
            "<img width=\"50\" height   =   \"60\">"
        ))),
        92600
    );
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
