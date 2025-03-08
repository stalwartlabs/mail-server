/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{FileItem, Files, Server};
use jmap_proto::types::collection::Collection;
use percent_encoding::NON_ALPHANUMERIC;
use trc::AddContext;
use utils::bimap::IdBimap;

use crate::file::FileNode;

pub trait FileHierarchy: Sync + Send {
    fn fetch_file_hierarchy(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<Files>>> + Send;
}

impl FileHierarchy for Server {
    async fn fetch_file_hierarchy(&self, account_id: u32) -> trc::Result<Arc<Files>> {
        let change_id = self
            .store()
            .get_last_change_id(account_id, Collection::FileNode)
            .await
            .caused_by(trc::location!())?;
        if let Some(files) = self
            .inner
            .cache
            .files
            .get(&account_id)
            .filter(|x| x.modseq == change_id)
        {
            Ok(files)
        } else {
            let mut files = build_file_hierarchy(self, account_id).await?;
            files.modseq = change_id;
            let files = Arc::new(files);
            self.inner.cache.files.insert(account_id, files.clone());
            Ok(files)
        }
    }
}

async fn build_file_hierarchy(server: &Server, account_id: u32) -> trc::Result<Files> {
    let list = server
        .fetch_folders::<FileNode>(account_id, Collection::FileNode)
        .await
        .caused_by(trc::location!())?
        .format(|f| {
            f.name = percent_encoding::utf8_percent_encode(&f.name, NON_ALPHANUMERIC).to_string();
        });
    let mut files = Files {
        files: IdBimap::with_capacity(list.len()),
        size: std::mem::size_of::<Files>() as u64,
        modseq: None,
    };

    for expanded in list.into_iterator() {
        files.size += (std::mem::size_of::<u32>()
            + std::mem::size_of::<String>()
            + expanded.name.len()) as u64;
        files.files.insert(FileItem {
            document_id: expanded.document_id,
            parent_id: expanded.parent_id,
            name: expanded.name,
            size: expanded.size,
            is_container: expanded.is_container,
            hierarchy_sequence: expanded.hierarchy_sequence,
        });
    }

    Ok(files)
}
