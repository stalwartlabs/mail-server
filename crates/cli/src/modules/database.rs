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
