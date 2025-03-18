/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use dav_proto::{
    Depth, RequestHeaders, Return,
    schema::request::{PropFind, SyncCollection},
};
use jmap_proto::types::property::Property;
use store::{
    U32_LEN,
    write::{Archive, BatchBuilder, MaybeDynamicValue, Operation, ValueClass, ValueOp},
};
use uri::OwnedUri;

pub mod acl;
pub mod lock;
pub mod propfind;
pub mod uri;

pub(crate) struct DavQuery<'x> {
    pub resource: OwnedUri<'x>,
    pub base_uri: &'x str,
    pub propfind: PropFind,
    pub from_change_id: Option<u64>,
    pub depth: usize,
    pub limit: Option<u32>,
    pub ret: Return,
    pub depth_no_root: bool,
}

pub trait ETag {
    fn etag(&self) -> String;
}

pub trait ExtractETag {
    fn etag(&self) -> Option<String>;
}

impl<T> ETag for Archive<T> {
    fn etag(&self) -> String {
        format!("\"{}\"", self.hash)
    }
}

impl ExtractETag for BatchBuilder {
    fn etag(&self) -> Option<String> {
        let p_value = u8::from(Property::Value);
        for op in self.ops.iter().rev() {
            match op {
                Operation::Value {
                    class: ValueClass::Property(p_id),
                    op: ValueOp::Set(MaybeDynamicValue::Static(value)),
                } if *p_id == p_value => {
                    return value
                        .get(value.len() - U32_LEN..)
                        .map(|v| format!("\"{}\"", u32::from_be_bytes(v.try_into().unwrap())));
                }
                _ => {}
            }
        }

        None
    }
}

impl<'x> DavQuery<'x> {
    pub fn propfind(
        resource: OwnedUri<'x>,
        propfind: PropFind,
        headers: RequestHeaders<'x>,
    ) -> Self {
        Self {
            resource,
            propfind,
            base_uri: headers.base_uri().unwrap_or_default(),
            from_change_id: None,
            depth: match headers.depth {
                Depth::Zero => 0,
                _ => 1,
            },
            limit: None,
            ret: headers.ret,
            depth_no_root: headers.depth_no_root,
        }
    }

    pub fn changes(
        resource: OwnedUri<'x>,
        changes: SyncCollection,
        headers: RequestHeaders<'x>,
    ) -> Self {
        Self {
            resource,
            propfind: changes.properties,
            base_uri: headers.base_uri().unwrap_or_default(),
            from_change_id: changes.sync_token.and_then(|s| s.parse().ok()),
            depth: if changes.level_inf { usize::MAX } else { 1 },
            limit: changes.limit,
            ret: headers.ret,
            depth_no_root: headers.depth_no_root,
        }
    }

    pub fn format_to_base_uri(&self, path: &str) -> String {
        format!("{}/{}", self.base_uri, path)
    }
}
