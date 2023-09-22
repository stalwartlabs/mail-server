use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};

use crate::smtp::session::TestSession;
use ahash::AHashMap;
use directory::config::ConfigDirectory;
use mail_auth::{dmarc::Policy, DkimResult, DmarcResult, IprevResult, SpfResult};
use sieve::runtime::Variable;
use smtp::{
    config::{scripts::ConfigSieve, ConfigContext, IfBlock},
    core::{Session, SessionAddress, SMTP},
    inbound::AuthResult,
    scripts::{
        functions::html::{get_attribute, html_img_area, html_to_tokens},
        ScriptResult,
    },
};
use tokio::runtime::Handle;
use utils::config::Config;

use crate::smtp::{TestConfig, TestSMTP};

const CONFIG: &str = r#"
[directory."sql"]
type = "sql"
address = "sqlite://%PATH%/test_antispam.db?mode=rwc"

[directory."sql".pool]
max-connections = 10
min-connections = 0
idle-timeout = "5m"

[sieve]
from-name = "Sieve Daemon"
from-addr = "sieve@foobar.org"
return-path = ""
hostname = "mx.foobar.org"
no-capability-check = true

[sieve.limits]
redirects = 3
out-messages = 5
received-headers = 50
cpu = 10000
nested-includes = 5
duplicate-expiry = "7d"

[sieve.scripts]
"#;

#[tokio::test]
async fn antispam() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
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
    ];
    let mut core = SMTP::test();
    let qr = core.init_test_queue("smtp_antispam_test");
    let mut config = CONFIG.replace("%PATH%", qr._temp_dir.temp_dir.as_path().to_str().unwrap());
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
        .join("resources")
        .join("config")
        .join("sieve")
        .to_str()
        .unwrap()
        .to_string();
    for test_name in tests {
        config.push_str(&format!(
            "{test_name} = \"file://{base_path}/{test_name}.sieve\"\n"
        ));
    }

    // Parse config
    let config = Config::parse(&config).unwrap();
    let mut ctx = ConfigContext::new(&[]);
    ctx.directory = config.parse_directory().unwrap();
    core.sieve = config.parse_sieve(&mut ctx).unwrap();
    let config = &mut core.session.config;
    config.rcpt.relay = IfBlock::new(true);
    let core = Arc::new(core);

    // Run tests
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("smtp")
        .join("antispam");
    let span = tracing::info_span!("sieve_antispam");
    for test_name in tests {
        println!("===== {test_name} =====");
        let script = ctx.scripts.remove(test_name).unwrap();

        let contents = fs::read_to_string(base_path.join(format!("{test_name}.test"))).unwrap();
        let mut lines = contents.lines();
        let mut has_more = true;

        while has_more {
            let mut message = String::new();
            let mut in_params = true;
            let mut variables = HashMap::new();
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
                                SpfResult::from_str(value).as_str().to_string(),
                            );
                        }
                        "iprev.result" => {
                            variables.insert(
                                param.to_string(),
                                IprevResult::from_str(value).as_str().to_string(),
                            );
                        }
                        "dkim.result" | "arc.result" => {
                            variables.insert(
                                param.to_string(),
                                DkimResult::from_str(value).as_str().to_string(),
                            );
                        }
                        "envelope_from" => {
                            session.data.mail_from = Some(SessionAddress::new(value.to_string()));
                        }
                        "iprev.ptr" | "dmarc.from" => {
                            variables.insert(param.to_string(), value.to_string());
                        }
                        "dmarc.result" => {
                            variables.insert(
                                param.to_string(),
                                DmarcResult::from_str(value).as_str().to_string(),
                            );
                        }
                        "dmarc.policy" => {
                            variables.insert(
                                param.to_string(),
                                Policy::from_str(value).as_str().to_string(),
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
                        _ if param.starts_with("param.") | param.starts_with("tls.") => {
                            variables.insert(param.to_string(), value.to_string());
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
                .build_script_parameters()
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
                Variable::String("<html".to_string()),
                Variable::String("_hello".to_string()),
                Variable::String("<br/".to_string()),
                Variable::String("_world".to_string()),
                Variable::String("<br/".to_string()),
                Variable::String("</html".to_string()),
            ],
        ),
        (
            "<html>using &lt;><br/></html>",
            vec![
                Variable::String("<html".to_string()),
                Variable::String("_using <>".to_string()),
                Variable::String("<br/".to_string()),
                Variable::String("</html".to_string()),
            ],
        ),
        (
            "test <not br/>tag<br />",
            vec![
                Variable::String("_test".to_string()),
                Variable::String("<not br/".to_string()),
                Variable::String("_ tag".to_string()),
                Variable::String("<br /".to_string()),
            ],
        ),
        (
            "<>< ><tag\n/>>hello    world< br \n />",
            vec![
                Variable::String("<".to_string()),
                Variable::String("<".to_string()),
                Variable::String("<tag /".to_string()),
                Variable::String("_>hello world".to_string()),
                Variable::String("<br /".to_string()),
            ],
        ),
        (
            concat!(
                "<head><title>ignore head</title><not head>xyz</not head></head>",
                "<h1>&lt;body&gt;</h1>"
            ),
            vec![
                Variable::String("<head".to_string()),
                Variable::String("<title".to_string()),
                Variable::String("_ignore head".to_string()),
                Variable::String("</title".to_string()),
                Variable::String("<not head".to_string()),
                Variable::String("_xyz".to_string()),
                Variable::String("</not head".to_string()),
                Variable::String("</head".to_string()),
                Variable::String("<h1".to_string()),
                Variable::String("_<body>".to_string()),
                Variable::String("</h1".to_string()),
            ],
        ),
        (
            concat!(
                "<p>what is &heartsuit;?</p><p>&#x000DF;&Abreve;&#914;&gamma; ",
                "don&apos;t hurt me.</p>"
            ),
            vec![
                Variable::String("<p".to_string()),
                Variable::String("_what is ♥?".to_string()),
                Variable::String("</p".to_string()),
                Variable::String("<p".to_string()),
                Variable::String("_ßĂΒγ don't hurt me.".to_string()),
                Variable::String("</p".to_string()),
            ],
        ),
        (
            concat!(
                "<!--[if mso]><style type=\"text/css\">body, table, td, a, p, ",
                "span, ul, li {font-family: Arial, sans-serif!important;}</style><![endif]-->",
                "this is <!-- <> < < < < ignore  > -> here -->the actual<!--> text"
            ),
            vec![
                Variable::String(
                    concat!(
                        "<!--[if mso]><style type=\"text/css\">body, table, ",
                        "td, a, p, span, ul, li {font-family: Arial, sans-serif!",
                        "important;}</style><![endif]--"
                    )
                    .to_string(),
                ),
                Variable::String("_this is".to_string()),
                Variable::String("<!-- <> < < < < ignore  > -> here --".to_string()),
                Variable::String("_ the actual".to_string()),
                Variable::String("<!--".to_string()),
                Variable::String("_ text".to_string()),
            ],
        ),
        (
            "   < p >  hello < / p > < p > world < / p >   !!! < br > ",
            vec![
                Variable::String("<p ".to_string()),
                Variable::String("_hello".to_string()),
                Variable::String("</p ".to_string()),
                Variable::String("<p ".to_string()),
                Variable::String("_ world".to_string()),
                Variable::String("</p ".to_string()),
                Variable::String("_ !!!".to_string()),
                Variable::String("<br ".to_string()),
            ],
        ),
        (
            " <p>please unsubscribe <a href=#>here</a>.</p> ",
            vec![
                Variable::String("<p".to_string()),
                Variable::String("_please unsubscribe".to_string()),
                Variable::String("<a href=#".to_string()),
                Variable::String("_ here".to_string()),
                Variable::String("</a".to_string()),
                Variable::String("_.".to_string()),
                Variable::String("</p".to_string()),
            ],
        ),
    ] {
        assert_eq!(html_to_tokens(input), expected, "Failed for '{:?}'", input);
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
