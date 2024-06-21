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

use hyper::Method;
use jmap_proto::error::request::RequestError;
use serde_json::json;
use store::ahash::AHashMap;
use utils::{config::ConfigKey, url_params::UrlParams};

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    JMAP,
};

use super::{decode_path_element, ManagementApiError};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum UpdateSettings {
    Delete {
        keys: Vec<String>,
    },
    Clear {
        prefix: String,
    },
    Insert {
        prefix: Option<String>,
        values: Vec<(String, String)>,
        assert_empty: bool,
    },
}

impl JMAP {
    pub async fn handle_manage_settings(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        match (path.get(1).copied(), req.method()) {
            (Some("group"), &Method::GET) => {
                // List settings
                let params = UrlParams::new(req.uri().query());
                let prefix = params
                    .get("prefix")
                    .map(|p| {
                        if !p.ends_with('.') {
                            format!("{p}.")
                        } else {
                            p.to_string()
                        }
                    })
                    .unwrap_or_default();
                let suffix = params
                    .get("suffix")
                    .map(|s| {
                        if !s.starts_with('.') {
                            format!(".{s}")
                        } else {
                            s.to_string()
                        }
                    })
                    .unwrap_or_default();
                let field = params.get("field");
                let filter = params.get("filter").unwrap_or_default().to_lowercase();
                let limit: usize = params.parse("limit").unwrap_or(0);
                let mut offset =
                    params.parse::<usize>("page").unwrap_or(0).saturating_sub(1) * limit;
                let has_filter = !filter.is_empty();

                match self.core.storage.config.list(&prefix, true).await {
                    Ok(settings) => if !suffix.is_empty() && !settings.is_empty() {
                        // Obtain record ids
                        let mut total = 0;
                        let mut ids = Vec::new();
                        for (key, _) in &settings {
                            if let Some(id) = key.strip_suffix(&suffix) {
                                if !id.is_empty() {
                                    if !has_filter {
                                        if offset == 0 {
                                            if limit == 0 || ids.len() < limit {
                                                ids.push(id);
                                            }
                                        } else {
                                            offset -= 1;
                                        }
                                        total += 1;
                                    } else {
                                        ids.push(id);
                                    }
                                }
                            }
                        }

                        // Group settings by record id
                        let mut records = Vec::new();
                        for id in ids {
                            let mut record = AHashMap::new();
                            let prefix = format!("{id}.");
                            record.insert("_id".to_string(), id.to_string());
                            for (k, v) in &settings {
                                if let Some(k) = k.strip_prefix(&prefix) {
                                    if field.map_or(true, |field| field == k) {
                                        record.insert(k.to_string(), v.to_string());
                                    }
                                } else if record.len() > 1 {
                                    break;
                                }
                            }

                            if has_filter {
                                if record
                                    .iter()
                                    .any(|(_, v)| v.to_lowercase().contains(&filter))
                                {
                                    if offset == 0 {
                                        if limit == 0 || records.len() < limit {
                                            records.push(record);
                                        }
                                    } else {
                                        offset -= 1;
                                    }
                                    total += 1;
                                }
                            } else {
                                records.push(record);
                            }
                        }

                        JsonResponse::new(json!({
                            "data": {
                                "total": total,
                                "items": records,
                            },
                        }))
                    } else {
                        let total = settings.len();
                        let items = settings
                            .into_iter()
                            .filter_map(|(k, v)| {
                                if filter.is_empty()
                                    || k.to_lowercase().contains(&filter)
                                    || v.to_lowercase().contains(&filter)
                                {
                                    let k =
                                        k.strip_prefix(&prefix).map(|k| k.to_string()).unwrap_or(k);
                                    Some(json!({
                                        "_id": k,
                                        "_value": v,
                                    }))
                                } else {
                                    None
                                }
                            })
                            .skip(offset)
                            .take(if limit == 0 { total } else { limit })
                            .collect::<Vec<_>>();

                        JsonResponse::new(json!({
                            "data": {
                                "total": total,
                                "items": items,
                            },
                        }))
                    }
                    .into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }
            (Some("list"), &Method::GET) => {
                // List settings
                let params = UrlParams::new(req.uri().query());
                let prefix = params
                    .get("prefix")
                    .map(|p| {
                        if !p.ends_with('.') {
                            format!("{p}.")
                        } else {
                            p.to_string()
                        }
                    })
                    .unwrap_or_default();
                let limit: usize = params.parse("limit").unwrap_or(0);
                let offset = params.parse::<usize>("page").unwrap_or(0).saturating_sub(1) * limit;

                match self.core.storage.config.list(&prefix, true).await {
                    Ok(settings) => {
                        let total = settings.len();
                        let items = settings
                            .into_iter()
                            .skip(offset)
                            .take(if limit == 0 { total } else { limit })
                            .collect::<AHashMap<_, _>>();

                        JsonResponse::new(json!({
                            "data": {
                                "total": total,
                                "items": items,
                            },
                        }))
                        .into_http_response()
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            (Some("keys"), &Method::GET) => {
                // Obtain keys
                let params = UrlParams::new(req.uri().query());
                let keys = params
                    .get("keys")
                    .map(|s| s.split(',').collect::<Vec<_>>())
                    .unwrap_or_default();
                let prefixes = params
                    .get("prefixes")
                    .map(|s| s.split(',').collect::<Vec<_>>())
                    .unwrap_or_default();
                let mut err = None;
                let mut results = AHashMap::with_capacity(keys.len());

                for key in keys {
                    match self.core.storage.config.get(key).await {
                        Ok(Some(value)) => {
                            results.insert(key.to_string(), value);
                        }
                        Ok(None) => {}
                        Err(err_) => {
                            err = err_.into();
                            break;
                        }
                    }
                }
                for prefix in prefixes {
                    let prefix = if !prefix.ends_with('.') {
                        format!("{prefix}.")
                    } else {
                        prefix.to_string()
                    };
                    match self.core.storage.config.list(&prefix, false).await {
                        Ok(values) => {
                            results.extend(values);
                        }
                        Err(err_) => {
                            err = err_.into();
                            break;
                        }
                    }
                }

                match err {
                    None => JsonResponse::new(json!({
                        "data": results,
                    }))
                    .into_http_response(),
                    Some(err) => err.into_http_response(),
                }
            }
            (Some(prefix), &Method::DELETE) if !prefix.is_empty() => {
                let prefix = decode_path_element(prefix);

                match self.core.storage.config.clear(prefix.as_ref()).await {
                    Ok(_) => JsonResponse::new(json!({
                        "data": (),
                    }))
                    .into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }
            (None, &Method::POST) => {
                match serde_json::from_slice::<Vec<UpdateSettings>>(
                    body.as_deref().unwrap_or_default(),
                ) {
                    Ok(changes) => {
                        let mut result = Ok(true);

                        'next: for change in changes {
                            match change {
                                UpdateSettings::Delete { keys } => {
                                    for key in keys {
                                        result =
                                            self.core.storage.config.clear(key).await.map(|_| true);
                                        if result.is_err() {
                                            break 'next;
                                        }
                                    }
                                }
                                UpdateSettings::Clear { prefix } => {
                                    result = self
                                        .core
                                        .storage
                                        .config
                                        .clear_prefix(&prefix)
                                        .await
                                        .map(|_| true);
                                    if result.is_err() {
                                        break;
                                    }
                                }
                                UpdateSettings::Insert {
                                    prefix,
                                    values,
                                    assert_empty,
                                } => {
                                    if assert_empty {
                                        if let Some(prefix) = &prefix {
                                            result = self
                                                .core
                                                .storage
                                                .config
                                                .list(&format!("{prefix}."), true)
                                                .await
                                                .map(|items| items.is_empty());

                                            if matches!(result, Ok(false) | Err(_)) {
                                                break;
                                            }
                                        } else if let Some((key, _)) = values.first() {
                                            result = self
                                                .core
                                                .storage
                                                .config
                                                .get(key)
                                                .await
                                                .map(|items| items.is_none());

                                            if matches!(result, Ok(false) | Err(_)) {
                                                break;
                                            }
                                        }
                                    }

                                    result = self
                                        .core
                                        .storage
                                        .config
                                        .set(values.into_iter().map(|(key, value)| ConfigKey {
                                            key: if let Some(prefix) = &prefix {
                                                format!("{prefix}.{key}")
                                            } else {
                                                key
                                            },
                                            value,
                                        }))
                                        .await
                                        .map(|_| true);
                                    if result.is_err() {
                                        break;
                                    }
                                }
                            }
                        }

                        match result {
                            Ok(true) => JsonResponse::new(json!({
                                "data": (),
                            }))
                            .into_http_response(),
                            Ok(false) => JsonResponse::new(ManagementApiError::AssertFailed)
                                .into_http_response(),
                            Err(err) => err.into_http_response(),
                        }
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            _ => RequestError::not_found().into_http_response(),
        }
    }
}
