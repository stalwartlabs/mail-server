/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write;

use jmap_proto::types::property::Property;
use store::write::{Archive, BatchBuilder, MaybeDynamicValue, Operation, ValueClass, ValueOp};

pub mod acl;
pub mod lock;
pub mod uri;

pub trait ETag {
    fn etag(&self) -> String;
}

pub trait ExtractETag {
    fn etag(&self) -> Option<String>;
}

impl<T: AsRef<[u8]>> ETag for T {
    fn etag(&self) -> String {
        let mut hasher = store::blake3::Hasher::new();
        hasher.update(self.as_ref());
        let hash = hasher.finalize();

        let mut etag = String::with_capacity(2 + hash.as_bytes().len() * 2);
        etag.push('"');
        for byte in hash.as_bytes() {
            let _ = write!(&mut etag, "{:02x}", byte);
        }
        etag.push('"');
        etag
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
                    return Archive::try_unpack_bytes(value).map(|bytes| bytes.etag());
                }
                _ => {}
            }
        }

        None
    }
}
