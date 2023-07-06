use jmap_client::client::Credentials;
use reqwest::header::AUTHORIZATION;

use super::{cli::DatabaseCommands, is_localhost, UnwrapResult};

pub async fn cmd_database(url: &str, credentials: Credentials, command: DatabaseCommands) {
    let url = match command {
        DatabaseCommands::Delete { account } => format!("{}/admin/account/delete/{}", url, account),
        DatabaseCommands::Rename {
            account,
            new_account,
        } => format!("{}/admin/account/rename/{}/{}", url, account, new_account),
        DatabaseCommands::Purge {} => format!("{}/admin/blob/purge", url),
    };

    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(is_localhost(&url))
        .build()
        .unwrap_or_default()
        .get(url)
        .header(
            AUTHORIZATION,
            match credentials {
                Credentials::Basic(s) => format!("Basic {s}"),
                Credentials::Bearer(s) => format!("Bearer {s}"),
            },
        )
        .send()
        .await
        .unwrap_result("send GET request");
    if response.status().is_success() {
        eprintln!("Success.");
    } else {
        eprintln!(
            "Request Failed: {}",
            response.text().await.unwrap_result("fetch text")
        );
    }
}
