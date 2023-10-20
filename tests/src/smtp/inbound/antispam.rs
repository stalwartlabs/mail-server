use std::{
    borrow::Cow,
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::smtp::session::TestSession;
use ahash::AHashMap;
use directory::config::ConfigDirectory;
use mail_auth::{dmarc::Policy, DkimResult, DmarcResult, IprevResult, SpfResult, MX};
use sieve::runtime::Variable;
use smtp::{
    config::{scripts::ConfigSieve, ConfigContext, IfBlock},
    core::{Session, SessionAddress, SMTP},
    inbound::AuthResult,
    scripts::{
        functions::html::{get_attribute, html_attr_tokens, html_img_area, html_to_tokens},
        ScriptResult,
    },
};
use tokio::runtime::Handle;
use utils::config::Config;

use crate::smtp::{TestConfig, TestSMTP};

const CONFIG: &str = r#"
[sieve.smtp]
from-name = "Sieve Daemon"
from-addr = "sieve@foobar.org"
return-path = ""
hostname = "mx.foobar.org"
no-capability-check = true

[sieve.smtp.limits]
redirects = 3
out-messages = 5
received-headers = 50
cpu = 10000
nested-includes = 5
duplicate-expiry = "7d"

[directory."spamdb"]
type = "sql"
address = "sqlite://%PATH%/test_antispam.db?mode=rwc"
#address = "sqlite:///tmp/test_antispam.db?mode=rwc"

[directory."spamdb".pool]
max-connections = 10
min-connections = 0
idle-timeout = "5m"

[directory."spamdb".lookup]
token-insert = "INSERT INTO bayes_tokens (h1, h2, ws, wh) VALUES (?, ?, ?, ?) 
                ON CONFLICT(h1, h2) 
                DO UPDATE SET ws = ws + excluded.ws, wh = wh + excluded.wh"
token-lookup = "SELECT ws, wh FROM bayes_tokens WHERE h1 = ? AND h2 = ?"
id-insert = "INSERT INTO seen_ids (id, ttl) VALUES (?, datetime('now', ? || ' seconds'))"
id-lookup = "SELECT 1 FROM seen_ids WHERE id = ? AND ttl > CURRENT_TIMESTAMP"
id-cleanup = "DELETE FROM seen_ids WHERE ttl < CURRENT_TIMESTAMP"
reputation-insert = "INSERT INTO reputation (token, score, count, ttl) VALUES (?, ?, 1, datetime('now', '30 days')) 
                     ON CONFLICT(token) 
                     DO UPDATE SET score = (count + 1) * (excluded.score + 0.98 * score) / (0.98 * count + 1), count = count + 1, ttl = excluded.ttl"
reputation-lookup = "SELECT score, count FROM reputation WHERE token = ?"
reputation-cleanup = "DELETE FROM reputation WHERE ttl < CURRENT_TIMESTAMP"

[directory."default"]
type = "memory"

[directory."default".lookup]
domains = ["local-domain.org"]

[directory."spam"]
type = "memory"

[directory."spam".lookup."free-domains"]
type = "glob"
comment = '#'
values = ["gmail.com", "googlemail.com", "yahoomail.com", "*.freemail.org"]

[directory."spam".lookup."disposable-domains"]
type = "glob"
comment = '#'
values = ["guerrillamail.com", "*.disposable.org"]

[directory."spam".lookup."redirectors"]
type = "glob"
comment = '#'
values = ["bit.ly", "redirect.io", "redirect.me", "redirect.org",
 "redirect.com", "redirect.net", "t.ly", "tinyurl.com"]

[directory."spam".lookup."dmarc-allow"]
type = "glob"
comment = '#'
values = ["dmarc-allow.org"]

[directory."spam".lookup."spf-dkim-allow"]
type = "glob"
comment = '#'
values = ["spf-dkim-allow.org"]

[directory."spam".lookup."domains-allow"]
type = "glob"
values = []

[directory."spam".lookup."mime-types"]
type = "map"
comment = '#'
values = ["html text/html|BAD", 
          "pdf application/pdf|NZ", 
          "txt text/plain|message/disposition-notification|text/rfc822-headers", 
          "zip AR", 
          "js BAD|NZ", 
          "hta BAD|NZ"]

[directory."spam".lookup."trap-address"]
type = "glob"
comment = '#'
values = ["spamtrap@*"]

[directory."spam".lookup."scores"]
type = "map"
values = ["SPAM_TRAP discard"]

[resolver]
public-suffix = "file://%LIST_PATH%/public-suffix.dat"

[sieve.smtp.scripts]
"#;

const CREATE_TABLES: &[&str; 3] = &[
    "CREATE TABLE IF NOT EXISTS bayes_tokens (
h1 INTEGER NOT NULL,
h2 INTEGER NOT NULL,
ws INTEGER,
wh INTEGER,
PRIMARY KEY (h1, h2)
)",
    "CREATE TABLE IF NOT EXISTS seen_ids (
    id STRING NOT NULL PRIMARY KEY,
    ttl DATETIME NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS reputation (
token STRING NOT NULL PRIMARY KEY,
score FLOAT NOT NULL DEFAULT '0',
count INT(11) NOT NULL DEFAULT '0',
ttl DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)",
];

#[tokio::test(flavor = "multi_thread")]
async fn antispam() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(
                tracing_subscriber::EnvFilter::builder()
                    .parse(
                        "smtp=debug,imap=debug,jmap=debug,store=debug,utils=debug,directory=debug",
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
    let mut core = SMTP::test();
    let qr = core.init_test_queue("smtp_antispam_test");
    let mut config = CONFIG
        .replace("%PATH%", qr._temp_dir.temp_dir.as_path().to_str().unwrap())
        .replace(
            "%LIST_PATH%",
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("smtp")
                .join("lists")
                .to_str()
                .unwrap(),
        );
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
        .join("resources")
        .join("config")
        .join("spamfilter")
        .join("scripts");
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
            "{test_name} = '''{script_config}\n{script_prelude}\n{script}\n'''\n"
        ));
    }

    config.push_str(&format!("combined = '''{all_scripts}\n'''\n"));

    // Parse config
    let config = Config::new(&config).unwrap();
    let mut ctx = ConfigContext::new(&[]);
    ctx.directory = config.parse_directory().unwrap();
    core.sieve = config.parse_sieve(&mut ctx).unwrap();
    let config = &mut core.session.config;
    config.rcpt.relay = IfBlock::new(true);

    // Create tables
    let sdb = ctx.directory.directories.get("spamdb").unwrap();
    for query in CREATE_TABLES {
        sdb.query(query, &[]).await.expect(query);
    }

    // Add mock DNS entries
    for (domain, ip) in [
        ("bank.com", "127.0.0.1"),
        ("apple.com", "127.0.0.1"),
        ("youtube.com", "127.0.0.1"),
        ("twitter.com", "127.0.0.3"),
        ("dkimtrusted.org.dwl.dnswl.org", "127.0.0.3"),
        ("sh-malware.com.dbl.spamhaus.org", "127.0.0.5"),
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
        core.resolvers.dns.ipv4_add(
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
        core.resolvers.dns.mx_add(
            mx,
            vec![MX {
                exchanges: vec!["127.0.0.1".parse().unwrap()],
                preference: 10,
            }],
            Instant::now() + Duration::from_secs(100),
        );
    }

    let core = Arc::new(core);

    // Run tests
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("smtp")
        .join("antispam");
    let span = tracing::info_span!("sieve_antispam");
    for &test_name in tests.iter().chain(&["combined"]) {
        /*if test_name != "combined" {
            continue;
        }*/
        println!("===== {test_name} =====");
        let script = ctx.scripts.remove(test_name).unwrap();

        let contents = fs::read_to_string(base_path.join(format!("{test_name}.test"))).unwrap();
        let mut lines = contents.lines();
        let mut has_more = true;

        while has_more {
            let mut message = String::new();
            let mut in_params = true;
            let mut variables: HashMap<String, Variable> = HashMap::new();
            let mut expected_variables = AHashMap::new();

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
                        "iprev.ptr" | "dmarc.from" => {
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
                .with_message(Arc::new(message.into_bytes()));
            for (name, value) in variables {
                params = params.set_variable(name, value);
            }

            // Run script
            let handle = Handle::current();
            let span = span.clone();
            let core_ = core.clone();
            let script = script.clone();
            match core
                .spawn_worker(move || core_.run_script_blocking(script, params, handle, span))
                .await
                .unwrap()
            {
                ScriptResult::Accept { .. } => {}
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
