/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::property::Property;
use store::{
    U32_LEN,
    write::{Archive, BatchBuilder, MaybeDynamicValue, Operation, ValueClass, ValueOp},
};

pub mod acl;
pub mod lock;
pub mod uri;

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
