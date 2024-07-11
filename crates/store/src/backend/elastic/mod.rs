/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use elasticsearch::{
    auth::Credentials,
    cert::CertificateValidation,
    http::{
        response::Response,
        transport::{SingleNodeConnectionPool, Transport, TransportBuilder},
        StatusCode, Url,
    },
    indices::{IndicesCreateParts, IndicesExistsParts},
    Elasticsearch, Error,
};
use serde_json::json;
use utils::config::{utils::AsKey, Config};

pub mod index;
pub mod query;

pub struct ElasticSearchStore {
    index: Elasticsearch,
}

pub(crate) static INDEX_NAMES: &[&str] = &["stalwart_email"];

impl ElasticSearchStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let credentials = if let Some(user) = config.value((&prefix, "user")) {
            let user = user.to_string();
            let password = config
                .value_require((&prefix, "password"))
                .unwrap_or_default();
            Some(Credentials::Basic(user, password.to_string()))
        } else {
            None
        };

        let es = if let Some(url) = config.value((&prefix, "url")) {
            let url = Url::parse(url)
                .map_err(|e| config.new_parse_error((&prefix, "url"), format!("Invalid URL: {e}",)))
                .ok()?;
            let conn_pool = SingleNodeConnectionPool::new(url);
            let mut builder = TransportBuilder::new(conn_pool);
            if let Some(credentials) = credentials {
                builder = builder.auth(credentials);
            }
            if config
                .property_or_default::<bool>((&prefix, "tls.allow-invalid-certs"), "false")
                .unwrap_or(false)
            {
                builder = builder.cert_validation(CertificateValidation::None);
            }

            Self {
                index: Elasticsearch::new(
                    builder
                        .build()
                        .map_err(|err| config.new_build_error(prefix.as_str(), err.to_string()))
                        .ok()?,
                ),
            }
        } else {
            let credentials = credentials.unwrap_or_else(|| {
                config.new_build_error((&prefix, "user"), "Missing property");
                Credentials::Basic("".to_string(), "".to_string())
            });

            if let Some(cloud_id) = config.value((&prefix, "cloud-id")) {
                Self {
                    index: Elasticsearch::new(
                        Transport::cloud(cloud_id, credentials)
                            .map_err(|err| config.new_build_error(prefix.as_str(), err.to_string()))
                            .ok()?,
                    ),
                }
            } else {
                config.new_parse_error(
                    prefix.as_str(),
                    "Missing url or cloud_id for ElasticSearch store",
                );
                return None;
            }
        };

        if let Err(err) = es
            .create_index(
                config
                    .property_or_default((&prefix, "index.shards"), "3")
                    .unwrap_or(3),
                config
                    .property_or_default((&prefix, "index.replicas"), "0")
                    .unwrap_or(0),
            )
            .await
        {
            config.new_build_error(prefix.as_str(), err.to_string());
        }

        Some(es)
    }

    async fn create_index(&self, shards: usize, replicas: usize) -> trc::Result<()> {
        let exists = self
            .index
            .indices()
            .exists(IndicesExistsParts::Index(&[INDEX_NAMES[0]]))
            .send()
            .await
            .map_err(|err| trc::Cause::ElasticSearch.reason(err))?;

        if exists.status_code() == StatusCode::NOT_FOUND {
            let response = self
                .index
                .indices()
                .create(IndicesCreateParts::Index(INDEX_NAMES[0]))
                .body(json!({
                  "mappings": {
                    "properties": {
                      "document_id": {
                        "type": "integer"
                      },
                      "account_id": {
                        "type": "integer"
                      },
                      "header": {
                        "type": "object",
                        "properties": {
                          "name": {
                            "type": "keyword"
                          },
                          "value": {
                            "type": "text",
                            "analyzer": "default_analyzer",
                          }
                        }
                      },
                      "body": {
                        "analyzer": "default_analyzer",
                        "type": "text"
                      },
                      "attachment": {
                        "analyzer": "default_analyzer",
                        "type": "text"
                      },
                      "keyword": {
                        "type": "keyword"
                      }
                    }
                  },
                  "settings": {
                    "index.number_of_shards": shards,
                    "index.number_of_replicas": replicas,
                    "analysis": {
                      "analyzer": {
                        "default_analyzer": {
                          "type": "custom",
                          "tokenizer": "standard",
                          "filter": ["lowercase"]
                        }
                      }
                    }
                  }
                }))
                .send()
                .await;

            assert_success(response).await?;
        }

        Ok(())
    }
}

pub(crate) async fn assert_success(response: Result<Response, Error>) -> trc::Result<Response> {
    match response {
        Ok(response) => {
            let status = response.status_code();
            if status.is_success() {
                Ok(response)
            } else {
                Err(trc::Cause::ElasticSearch
                    .reason(response.text().await.unwrap_or_default())
                    .ctx(trc::Key::Code, status.as_u16()))
            }
        }
        Err(err) => Err(trc::Cause::ElasticSearch.reason(err)),
    }
}
