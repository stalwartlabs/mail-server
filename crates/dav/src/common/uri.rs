/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use common::{Server, auth::AccessToken};

use directory::backend::internal::manage::ManageDirectory;
use http_proto::request::decode_path_element;
use hyper::StatusCode;
use jmap_proto::types::collection::Collection;
use trc::AddContext;

use crate::{DavError, DavResource};

pub(crate) struct UriResource<A, R> {
    pub collection: Collection,
    pub account_id: A,
    pub resource: R,
}

pub(crate) enum Urn {
    Lock { expires: u64, id: u64 },
    Sync { id: u64 },
}

pub(crate) type UnresolvedUri<'x> = UriResource<Option<u32>, Option<&'x str>>;
pub(crate) type OwnedUri<'x> = UriResource<u32, Option<&'x str>>;
//pub(crate) type DocumentUri<'x> = UriResource<u32, u32>;

pub(crate) trait DavUriResource: Sync + Send {
    fn validate_uri<'x>(
        &self,
        access_token: &AccessToken,
        uri: &'x str,
    ) -> impl Future<Output = crate::Result<UnresolvedUri<'x>>> + Send;
}

impl DavUriResource for Server {
    async fn validate_uri<'x>(
        &self,
        access_token: &AccessToken,
        uri: &'x str,
    ) -> crate::Result<UnresolvedUri<'x>> {
        let (_, uri_parts) = uri
            .split_once("/dav/")
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        let mut uri_parts = uri_parts
            .trim_end_matches('/')
            .splitn(3, '/')
            .filter(|x| !x.is_empty());
        let mut resource = UriResource {
            collection: uri_parts
                .next()
                .and_then(DavResource::parse)
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
                .into(),
            account_id: None,
            resource: None,
        };
        if let Some(account) = uri_parts.next() {
            // Parse account id
            let account_id = if let Some(account_id) = account.strip_prefix('_') {
                account_id
                    .parse::<u32>()
                    .map_err(|_| DavError::Code(StatusCode::NOT_FOUND))?
            } else {
                let account = decode_path_element(account);
                if access_token.name == account {
                    access_token.primary_id
                } else {
                    self.store()
                        .get_principal_id(&account)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?
                }
            };

            // Validate access
            if resource.collection != Collection::Principal
                && !access_token.has_access(account_id, resource.collection)
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Obtain remaining path
            resource.account_id = Some(account_id);
            resource.resource = uri_parts.next();
        }

        Ok(resource)
    }
}

impl<'x> UnresolvedUri<'x> {
    pub fn into_owned_uri(self) -> crate::Result<OwnedUri<'x>> {
        Ok(OwnedUri {
            collection: self.collection,
            account_id: self
                .account_id
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?,
            resource: self.resource,
        })
    }
}

impl OwnedUri<'_> {
    pub fn new_owned(
        collection: Collection,
        account_id: u32,
        resource: Option<&str>,
    ) -> OwnedUri<'_> {
        OwnedUri {
            collection,
            account_id,
            resource,
        }
    }
}

impl Urn {
    pub fn parse(input: &str) -> Option<Self> {
        let inbox = input.strip_prefix("urn:stalwart:")?;
        let (kind, id) = inbox.split_once(':')?;
        match kind {
            "davlock" => u128::from_str_radix(id, 16).ok().map(|id| Urn::Lock {
                expires: (id >> 64) as u64,
                id: id as u64,
            }),
            "davsync" => u64::from_str_radix(id, 16).ok().map(|id| Urn::Sync { id }),
            _ => None,
        }
    }

    pub fn try_unwrap_lock(&self) -> Option<(u64, u64)> {
        match self {
            Urn::Lock { expires, id } => Some((*expires, *id)),
            _ => None,
        }
    }

    pub fn try_unwrap_sync(&self) -> Option<u64> {
        match self {
            Urn::Sync { id } => Some(*id),
            _ => None,
        }
    }
}

impl Display for Urn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Urn::Lock { expires, id } => write!(
                f,
                "urn:stalwart:davlock:{:x}",
                (u128::from(*expires) << 64) | u128::from(*id)
            ),
            Urn::Sync { id } => write!(f, "urn:stalwart:davsync:{:x}", id),
        }
    }
}
