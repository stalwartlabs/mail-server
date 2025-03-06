/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::Files;
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

pub(crate) trait DavFileResource {
    fn map_resource(&self, resource: UriResource<Option<&str>>) -> crate::Result<UriResource<u32>>;

    fn map_resource_or_root(
        &self,
        resource: UriResource<Option<&str>>,
    ) -> crate::Result<UriResource<Option<u32>>>;

    fn map_parent<'x>(&self, resource: &'x str) -> crate::Result<(Option<u32>, Cow<'x, str>)>;

    fn map_parent_resource<'x>(
        &self,
        resource: UriResource<Option<&'x str>>,
    ) -> crate::Result<UriResource<(Option<u32>, Cow<'x, str>)>>;
}

impl DavFileResource for Files {
    fn map_resource(&self, resource: UriResource<Option<&str>>) -> crate::Result<UriResource<u32>> {
        resource
            .resource
            .and_then(|r| self.files.by_name(r))
            .map(|r| UriResource {
                collection: resource.collection,
                account_id: resource.account_id,
                resource: r,
            })
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))
    }

    fn map_resource_or_root(
        &self,
        resource: UriResource<Option<&str>>,
    ) -> crate::Result<UriResource<Option<u32>>> {
        Ok(UriResource {
            collection: resource.collection,
            account_id: resource.account_id,
            resource: if let Some(resource) = resource.resource {
                Some(
                    self.files
                        .by_name(resource)
                        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?,
                )
            } else {
                None
            },
        })
    }

    fn map_parent<'x>(&self, resource: &'x str) -> crate::Result<(Option<u32>, Cow<'x, str>)> {
        let (parent, child) = if let Some((parent, child)) = resource.rsplit_once('/') {
            (
                Some(
                    self.files
                        .by_name(parent)
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

    fn map_parent_resource<'x>(
        &self,
        resource: UriResource<Option<&'x str>>,
    ) -> crate::Result<UriResource<(Option<u32>, Cow<'x, str>)>> {
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
