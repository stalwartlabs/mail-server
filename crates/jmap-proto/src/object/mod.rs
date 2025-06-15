/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use utils::{
    erased_serde,
    json::{JsonPointerItem, JsonQueryable},
};

use crate::types::{
    id::Id,
    property::Property,
    value::{Object, Value},
};

pub mod blob;
pub mod email;
pub mod email_submission;
pub mod mailbox;
pub mod sieve;

pub trait JsonObjectTrait: JsonQueryable + erased_serde::Serialize {
    fn id(&self) -> Option<Id>;
}

#[derive(Clone, Debug)]
pub struct JsonObject(Arc<dyn JsonObjectTrait>);

impl JsonObject {
    pub fn new<T: JsonObjectTrait + 'static>(value: T) -> Self {
        Self(Arc::new(value))
    }

    #[inline]
    pub fn id(&self) -> Option<Id> {
        self.0.id()
    }
}

impl serde::Serialize for JsonObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        erased_serde::serialize(self.0.as_ref(), serializer)
    }
}

impl JsonObjectTrait for Object<Value> {
    fn id(&self) -> Option<Id> {
        self.get(&Property::Id).as_id().copied()
    }
}

impl JsonQueryable for Object<Value> {
    fn eval_pointer<'x>(
        &'x self,
        mut pointer: std::slice::Iter<utils::json::JsonPointerItem>,
        results: &mut Vec<&'x dyn JsonQueryable>,
    ) {
        match pointer.next() {
            Some(JsonPointerItem::String(n)) => {
                if let Some(v) = self
                    .0
                    .iter()
                    .find_map(|(k, v)| if k.as_str() == n { Some(v) } else { None })
                {
                    v.eval_pointer(pointer, results);
                }
            }
            Some(JsonPointerItem::Wildcard) => {
                for v in self.0.values() {
                    v.eval_pointer(pointer.clone(), results);
                }
            }
            Some(JsonPointerItem::Root) | None => {
                results.push(self);
            }
            _ => {}
        }
    }
}
