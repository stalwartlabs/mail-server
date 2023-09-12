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
    scripts::ScriptResult,
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

[sieve.limits]
redirects = 3
out-messages = 5
received-headers = 50
cpu = 10000
nested-includes = 5
duplicate-expiry = "7d"

[sieve.scripts]
data = "file://%CFG_PATH%/config/sieve/antispam.sieve"
"#;

#[tokio::test]
async fn antispam() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Parse config
    let mut core = SMTP::test();
    let qr = core.init_test_queue("smtp_antispam_test");
    let config = Config::parse(
        &CONFIG
            .replace("%PATH%", qr._temp_dir.temp_dir.as_path().to_str().unwrap())
            .replace(
                "%CFG_PATH%",
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .to_path_buf()
                    .join("resources")
                    .as_path()
                    .to_str()
                    .unwrap(),
            ),
    )
    .unwrap();
    let mut ctx = ConfigContext::new(&[]);
    ctx.directory = config.parse_directory().unwrap();
    core.sieve = config.parse_sieve(&mut ctx).unwrap();
    let config = &mut core.session.config;
    config.rcpt.relay = IfBlock::new(true);
    let core = Arc::new(core);
    let script = ctx.scripts.get("data").unwrap().clone();

    // Run tests
    let span = tracing::info_span!("sieve_antispam");
    for file_name in fs::read_dir(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("smtp")
            .join("antispam"),
    )
    .unwrap()
    {
        let file_name = file_name.unwrap().path();

        println!("===== {} =====", file_name.display());

        let contents = fs::read_to_string(&file_name).unwrap();
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
                        "spf_result" | "spf_ehlo_result" => {
                            variables.insert(
                                param.to_string(),
                                SpfResult::from_str(value).as_str().to_string(),
                            );
                        }
                        "iprev_result" => {
                            variables.insert(
                                param.to_string(),
                                IprevResult::from_str(value).as_str().to_string(),
                            );
                        }
                        "dkim_result" | "arc_result" => {
                            variables.insert(
                                param.to_string(),
                                DkimResult::from_str(value).as_str().to_string(),
                            );
                        }
                        "envelope_from" => {
                            session.data.mail_from = Some(SessionAddress::new(value.to_string()));
                        }
                        "iprev_ptr" | "dmarc_from" => {
                            variables.insert(param.to_string(), value.to_string());
                        }
                        "dmarc_result" => {
                            variables.insert(
                                param.to_string(),
                                DmarcResult::from_str(value).as_str().to_string(),
                            );
                        }
                        "dmarc_policy" => {
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
