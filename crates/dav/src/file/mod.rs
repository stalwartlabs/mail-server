/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::{FileItem, Files};
use hyper::StatusCode;

use crate::{DavError, common::uri::UriResource};

pub mod acl;
pub mod changes;
pub mod copy_move;
pub mod delete;
pub mod get;
pub mod lock;
pub mod mkcol;
pub mod propfind;
pub mod proppatch;
pub mod update;

pub(crate) trait FromFileItem {
    fn from_file_item(item: &FileItem) -> Self;
}

pub(crate) struct FileItemId {
    pub document_id: u32,
    pub parent_id: Option<u32>,
    pub is_container: bool,
}

pub(crate) trait DavFileResource {
    fn map_resource<T: FromFileItem>(
        &self,
        resource: UriResource<Option<&str>>,
    ) -> crate::Result<UriResource<T>>;

    fn map_destination<T: FromFileItem>(
        &self,
        resource: UriResource<Option<&str>>,
    ) -> crate::Result<UriResource<Option<T>>>;

    fn map_parent<'x, T: FromFileItem>(
        &self,
        resource: &'x str,
    ) -> crate::Result<(Option<T>, Cow<'x, str>)>;

    fn map_parent_resource<'x, T: FromFileItem>(
        &self,
        resource: UriResource<Option<&'x str>>,
    ) -> crate::Result<UriResource<(Option<T>, Cow<'x, str>)>>;
}

impl DavFileResource for Files {
    fn map_resource<T: FromFileItem>(
        &self,
        resource: UriResource<Option<&str>>,
    ) -> crate::Result<UriResource<T>> {
        resource
            .resource
            .and_then(|r| self.files.by_name(r))
            .map(|r| UriResource {
                collection: resource.collection,
                account_id: resource.account_id,
                resource: T::from_file_item(r),
            })
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))
    }

    fn map_destination<T: FromFileItem>(
        &self,
        resource: UriResource<Option<&str>>,
    ) -> crate::Result<UriResource<Option<T>>> {
        Ok(UriResource {
            collection: resource.collection,
            account_id: resource.account_id,
            resource: if let Some(resource) = resource.resource {
                Some(
                    self.files
                        .by_name(resource)
                        .map(T::from_file_item)
                        .ok_or(DavError::Code(StatusCode::BAD_GATEWAY))?,
                )
            } else {
                None
            },
        })
    }

    fn map_parent<'x, T: FromFileItem>(
        &self,
        resource: &'x str,
    ) -> crate::Result<(Option<T>, Cow<'x, str>)> {
        let (parent, child) = if let Some((parent, child)) = resource.rsplit_once('/') {
            (
                Some(
                    self.files
                        .by_name(parent)
                        .map(T::from_file_item)
                        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?,
                ),
                child,
            )
        } else {
            (None, resource)
        };

        Ok((
            parent,
            percent_encoding::percent_decode_str(child)
                .decode_utf8()
                .unwrap_or_else(|_| child.into()),
        ))
    }

    fn map_parent_resource<'x, T: FromFileItem>(
        &self,
        resource: UriResource<Option<&'x str>>,
    ) -> crate::Result<UriResource<(Option<T>, Cow<'x, str>)>> {
        if let Some(r) = resource.resource {
            if self.files.by_name(r).is_none() {
                self.map_parent(r).map(|r| UriResource {
                    collection: resource.collection,
                    account_id: resource.account_id,
                    resource: r,
                })
            } else {
                Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
            }
        } else {
            Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))
        }
    }
}

impl FromFileItem for u32 {
    fn from_file_item(item: &FileItem) -> Self {
        item.document_id
    }
}

impl FromFileItem for FileItemId {
    fn from_file_item(item: &FileItem) -> Self {
        FileItemId {
            document_id: item.document_id,
            parent_id: item.parent_id,
            is_container: item.is_container,
        }
    }
}
