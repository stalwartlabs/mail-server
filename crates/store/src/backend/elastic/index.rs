/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display};

use elasticsearch::{DeleteByQueryParts, IndexParts};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    backend::elastic::INDEX_NAMES,
    dispatch::DocumentSet,
    fts::{index::FtsDocument, Field},
};

use super::{assert_success, ElasticSearchStore};

#[derive(Serialize, Deserialize, Default)]
struct Document<'x> {
    document_id: u32,
    account_id: u32,
    body: Vec<Cow<'x, str>>,
    attachments: Vec<Cow<'x, str>>,
    keywords: Vec<Cow<'x, str>>,
    header: Vec<Header<'x>>,
}

#[derive(Serialize, Deserialize)]
struct Header<'x> {
    name: Cow<'x, str>,
    value: Cow<'x, str>,
}

impl ElasticSearchStore {
    pub async fn fts_index<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        document: FtsDocument<'_, T>,
    ) -> trc::Result<()> {
        assert_success(
            self.index
                .index(IndexParts::Index(INDEX_NAMES[document.collection as usize]))
                .body(Document::from(document))
                .send()
                .await,
        )
        .await
        .map(|_| ())
    }

    pub async fn fts_remove(
        &self,
        account_id: u32,
        collection: u8,
        document_ids: &impl DocumentSet,
    ) -> trc::Result<()> {
        let document_ids = document_ids.iterate().collect::<Vec<_>>();

        assert_success(
            self.index
                .delete_by_query(DeleteByQueryParts::Index(&[
                    INDEX_NAMES[collection as usize]
                ]))
                .body(json!({
                    "query": {
                        "bool": {
                            "must": [
                                { "match": { "account_id": account_id } },
                                { "terms": { "document_id": document_ids } }
                            ]
                        }
                    }
                }))
                .send()
                .await,
        )
        .await
        .map(|_| ())
    }

    pub async fn fts_remove_all(&self, account_id: u32) -> trc::Result<()> {
        assert_success(
            self.index
                .delete_by_query(DeleteByQueryParts::Index(INDEX_NAMES))
                .body(json!({
                    "query": {
                        "bool": {
                            "must": [
                                { "match": { "account_id": account_id } },
                            ]
                        }
                    }
                }))
                .send()
                .await,
        )
        .await
        .map(|_| ())
    }
}

impl<'x, T: Into<u8> + Display + Clone + std::fmt::Debug> From<FtsDocument<'x, T>>
    for Document<'x>
{
    fn from(value: FtsDocument<'x, T>) -> Self {
        let mut document = Document {
            account_id: value.account_id,
            document_id: value.document_id,
            ..Default::default()
        };

        for part in value.parts {
            match part.field {
                Field::Header(name) => document.header.push(Header {
                    name: name.to_string().into(),
                    value: part.text,
                }),
                Field::Body => document.body.push(part.text),
                Field::Attachment => document.attachments.push(part.text),
                Field::Keyword => document.keywords.push(part.text),
            }
        }

        document
    }
}
