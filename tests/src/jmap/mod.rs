use std::{sync::Arc, time::Duration};

use jmap::{api::SessionManager, JMAP};
use jmap_client::client::{Client, Credentials};
use jmap_proto::types::id::Id;
use tokio::sync::watch;

use crate::{add_test_certs, store::TempDir};

pub mod email_get;
pub mod email_query;
pub mod email_set;
pub mod mailbox;
pub mod thread_get;
pub mod thread_merge;

const SERVER: &str = "
[server]
hostname = 'jmap.example.org'

[server.listener.jmap]
bind = ['127.0.0.1:8899']
url = 'https://127.0.0.1:8899'
protocol = 'jmap'

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = 'default'

[store]
db.path = '{TMP}/sqlite.db'
blob.path = '{TMP}'

[certificate.default]
cert = 'file://{CERT}'
private-key = 'file://{PK}'
";

#[tokio::test]
pub async fn jmap_tests() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::WARN)
            .finish(),
    )
    .unwrap();

    let delete = true;
    let mut params = init_jmap_tests(delete).await;
    //email_get::test(params.server.clone(), &mut params.client).await;
    //email_set::test(params.server.clone(), &mut params.client).await;
    //email_query::test(params.server.clone(), &mut params.client, delete).await;
    //thread_get::test(params.server.clone(), &mut params.client).await;
    //thread_merge::test(params.server.clone(), &mut params.client).await;
    mailbox::test(params.server.clone(), &mut params.client).await;
    if delete {
        params.temp_dir.delete();
    }
}

#[allow(dead_code)]
struct JMAPTest {
    server: Arc<JMAP>,
    client: Client,
    temp_dir: TempDir,
    shutdown_tx: watch::Sender<bool>,
}

async fn init_jmap_tests(delete_if_exists: bool) -> JMAPTest {
    // Load and parse config
    let temp_dir = TempDir::new("jmap_tests", delete_if_exists);
    let settings = utils::config::Config::parse(
        &add_test_certs(SERVER).replace("{TMP}", &temp_dir.path.display().to_string()),
    )
    .unwrap();
    let servers = settings.parse_servers().unwrap();

    // Start JMAP server
    let manager = SessionManager::from(JMAP::new(&settings).await);
    let shutdown_tx = servers.spawn(&settings, |server, shutdown_rx| {
        server.spawn(manager.clone(), shutdown_rx);
    });

    // Create client
    let mut client = Client::new()
        .credentials(Credentials::bearer("DO_NOT_ATTEMPT_THIS_AT_HOME"))
        .timeout(Duration::from_secs(60))
        .accept_invalid_certs(true)
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    client.set_default_account_id(Id::new(1));

    JMAPTest {
        server: manager.inner,
        temp_dir,
        client,
        shutdown_tx,
    }
}

pub fn find_values(string: &str, name: &str) -> Vec<String> {
    let mut last_pos = 0;
    let mut values = Vec::new();

    while let Some(pos) = string[last_pos..].find(name) {
        let mut value = string[last_pos + pos + name.len()..]
            .split('"')
            .nth(1)
            .unwrap();
        if value.ends_with('\\') {
            value = &value[..value.len() - 1];
        }
        values.push(value.to_string());
        last_pos += pos + name.len();
    }

    values
}

pub fn replace_values(mut string: String, find: &[String], replace: &[String]) -> String {
    for (find, replace) in find.iter().zip(replace.iter()) {
        string = string.replace(find, replace);
    }
    string
}

pub fn replace_boundaries(string: String) -> String {
    let values = find_values(&string, "boundary=");
    if !values.is_empty() {
        replace_values(
            string,
            &values,
            &(0..values.len())
                .map(|i| format!("boundary_{}", i))
                .collect::<Vec<_>>(),
        )
    } else {
        string
    }
}

pub fn replace_blob_ids(string: String) -> String {
    let values = find_values(&string, "blobId\":");
    if !values.is_empty() {
        replace_values(
            string,
            &values,
            &(0..values.len())
                .map(|i| format!("blob_{}", i))
                .collect::<Vec<_>>(),
        )
    } else {
        string
    }
}
