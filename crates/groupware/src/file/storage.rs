/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use jmap_proto::types::collection::{Collection, VanishedCollection};
use store::write::{Archive, BatchBuilder, now};
use trc::AddContext;

use crate::DestroyArchive;

use super::{ArchivedFileNode, FileNode};

impl FileNode {
    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build node
        let mut node = self;
        let now = now() as i64;
        node.modified = now;
        node.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode)
            .create_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(node)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }
    pub fn update<'x>(
        self,
        access_token: &AccessToken,
        node: Archive<&ArchivedFileNode>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build node
        let mut new_node = self;
        new_node.modified = now() as i64;
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode)
            .update_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(node)
                    .with_changes(new_node)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }
}

impl DestroyArchive<Archive<&ArchivedFileNode>> {
    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
        path: String,
    ) -> trc::Result<()> {
        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode)
            .delete_document(document_id)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_current(self.0)
                    .with_tenant_id(access_token),
            )?
            .log_vanished_item(VanishedCollection::FileNode, path)
            .commit_point();
        Ok(())
    }
}

impl DestroyArchive<Vec<u32>> {
    pub async fn delete(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        delete_path: Option<String>,
    ) -> trc::Result<()> {
        // Process deletions
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::FileNode);
        for document_id in self.0 {
            if let Some(node) = server
                .get_archive(account_id, Collection::FileNode, document_id)
                .await?
            {
                // Delete record
                batch
                    .delete_document(document_id)
                    .custom(
                        ObjectIndexBuilder::<_, ()>::new()
                            .with_tenant_id(access_token)
                            .with_current(
                                node.to_unarchived::<FileNode>()
                                    .caused_by(trc::location!())?,
                            ),
                    )
                    .caused_by(trc::location!())?
                    .commit_point();
            }
        }

        // Write changes
        if !batch.is_empty() {
            if let Some(delete_path) = delete_path {
                batch.log_vanished_item(VanishedCollection::FileNode, delete_path);
            }
            server
                .commit_batch(batch)
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }
}
