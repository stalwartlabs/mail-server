/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use elasticsearch::{
    auth::Credentials,
    cert::CertificateValidation,
    http::{
        transport::{BuildError, SingleNodeConnectionPool, Transport, TransportBuilder},
        StatusCode, Url,
    },
    indices::{IndicesCreateParts, IndicesExistsParts},
    Elasticsearch, Error,
};
use serde_json::json;
use utils::config::Config;

pub mod index;
pub mod query;

pub struct ElasticSearchStore {
    index: Elasticsearch,
}

pub(crate) static INDEX_NAMES: &[&str] = &["stalwart_email"];

impl ElasticSearchStore {
    pub async fn open(config: &Config) -> crate::Result<Self> {
        let credentials = if let Some(user) = config.value("store.fts.user") {
            let password = config.value_require("store.fts.password")?;
            Some(Credentials::Basic(user.to_string(), password.to_string()))
        } else {
            None
        };

        let es = if let Some(url) = config.value("store.fts.url") {
            let url = Url::parse(url).map_err(|e| {
                crate::Error::InternalError(format!("Invalid store.fts.url: {}", e))
            })?;
            let conn_pool = SingleNodeConnectionPool::new(url);
            let mut builder = TransportBuilder::new(conn_pool);
            if let Some(credentials) = credentials {
                builder = builder.auth(credentials);
            }
            if config.property_or_static::<bool>("store.fts.allow-invalid-certs", "false")? {
                builder = builder.cert_validation(CertificateValidation::None);
            }

            Self {
                index: Elasticsearch::new(builder.build()?),
            }
        } else if let Some(cloud_id) = config.value("store.fts.cloud-id") {
            Self {
                index: Elasticsearch::new(Transport::cloud(
                    cloud_id,
                    credentials.ok_or_else(|| {
                        crate::Error::InternalError(
                            "Missing store.fts.user or store.fts.password".to_string(),
                        )
                    })?,
                )?),
            }
        } else {
            return Err(crate::Error::InternalError(
                "Missing store.fts.url or store.fts.cloud_id".to_string(),
            ));
        };

        es.create_index(
            config.property_or_static("store.fts.shards", "3")?,
            config.property_or_static("store.fts.replicas", "0")?,
        )
        .await?;

        Ok(es)
    }

    async fn create_index(&self, shards: usize, replicas: usize) -> crate::Result<()> {
        let exists = self
            .index
            .indices()
            .exists(IndicesExistsParts::Index(&[INDEX_NAMES[0]]))
            .send()
            .await?;

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
                .await?;

            if !response.status_code().is_success() {
                return Err(crate::Error::InternalError(format!(
                    "Error while creating ElastiSearch index: {:?}",
                    response
                )));
            }
        }

        Ok(())
    }
}

impl From<Error> for crate::Error {
    fn from(value: Error) -> Self {
        crate::Error::InternalError(format!("Elasticsearch error: {}", value))
    }
}

impl From<BuildError> for crate::Error {
    fn from(value: BuildError) -> Self {
        crate::Error::InternalError(format!("Elasticsearch build error: {}", value))
    }
}
