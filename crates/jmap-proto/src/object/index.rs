/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{borrow::Cow, collections::HashSet};

use store::{
    fts::builder::ToTokens,
    write::{assert::HashedValue, BatchBuilder, BitmapFamily, IntoOperations, Operation},
    Serialize, HASH_EXACT,
};

use crate::{
    error::set::SetError,
    types::{id::Id, property::Property, value::Value},
};

use super::Object;

#[derive(Debug, Clone, Default)]
pub struct ObjectIndexBuilder {
    index: &'static [IndexProperty],
    current: Option<HashedValue<Object<Value>>>,
    changes: Option<Object<Value>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum IndexAs {
    Text {
        tokenize: bool,
        index: bool,
    },
    TextList {
        tokenize: bool,
        index: bool,
    },
    Integer,
    IntegerList,
    LongInteger,
    HasProperty,
    Acl,
    Quota,
    #[default]
    None,
}

#[derive(Debug, Clone)]
pub struct IndexProperty {
    property: Property,
    index_as: IndexAs,
    required: bool,
    max_size: usize,
}

impl ObjectIndexBuilder {
    pub fn new(index: &'static [IndexProperty]) -> Self {
        Self {
            index,
            current: None,
            changes: None,
        }
    }

    pub fn with_current(mut self, current: HashedValue<Object<Value>>) -> Self {
        self.current = Some(current);
        self
    }

    pub fn with_changes(mut self, changes: Object<Value>) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn with_current_opt(mut self, current: Option<HashedValue<Object<Value>>>) -> Self {
        self.current = current;
        self
    }

    pub fn get(&self, property: &Property) -> &Value {
        self.changes
            .as_ref()
            .and_then(|c| c.properties.get(property))
            .or_else(|| {
                self.current
                    .as_ref()
                    .and_then(|c| c.inner.properties.get(property))
            })
            .unwrap_or(&Value::Null)
    }

    pub fn set(&mut self, property: Property, value: Value) {
        if let Some(changes) = &mut self.changes {
            changes.properties.set(property, value);
        }
    }

    pub fn validate(self) -> Result<Self, SetError> {
        for item in self.index {
            if item.required || item.max_size > 0 {
                let error: Cow<str> = match self.get(&item.property) {
                    Value::Null if item.required => "Property cannot be empty.".into(),
                    Value::Text(text) => {
                        if item.required && text.trim().is_empty() {
                            "Property cannot be empty.".into()
                        } else if item.max_size > 0 && text.len() > item.max_size {
                            format!("Property cannot be longer than {} bytes.", item.max_size)
                                .into()
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                };
                return Err(SetError::invalid_properties()
                    .with_property(item.property.clone())
                    .with_description(error));
            }
        }

        Ok(self)
    }
}

impl IntoOperations for ObjectIndexBuilder {
    fn build(self, batch: &mut BatchBuilder) {
        match (self.current, self.changes) {
            (None, Some(changes)) => {
                // Insertion
                build_batch(batch, self.index, &changes, true);
                batch.ops.push(Operation::Value {
                    field: Property::Value.into(),
                    family: 0,
                    set: changes.serialize().into(),
                });
            }
            (Some(current), Some(changes)) => {
                // Update
                batch.assert_value(Property::Value, &current);
                merge_batch(batch, self.index, current.inner, changes);
            }
            (Some(current), None) => {
                // Deletion
                batch.assert_value(Property::Value, &current);
                build_batch(batch, self.index, &current.inner, false);
                batch.ops.push(Operation::Value {
                    field: Property::Value.into(),
                    family: 0,
                    set: None,
                });
            }
            (None, None) => unreachable!(),
        }
    }
}

fn merge_batch(
    batch: &mut BatchBuilder,
    index: &'static [IndexProperty],
    mut current: Object<Value>,
    changes: Object<Value>,
) {
    let mut has_changes = false;

    for (property, value) in changes.properties {
        let current_value = current.get(&property);
        if current_value == &value {
            continue;
        }

        for index_property in index {
            if index_property.property != property {
                continue;
            }
            match index_property.index_as {
                IndexAs::Text { tokenize, index } => {
                    // Remove current text from index
                    let mut add_tokens = HashSet::new();
                    let mut remove_tokens = HashSet::new();
                    if let Some(text) = current_value.as_string() {
                        if index {
                            batch.ops.push(Operation::Index {
                                field: property.clone().into(),
                                key: text.serialize(),
                                set: false,
                            });
                        }
                        if tokenize {
                            remove_tokens = text.to_tokens();
                        }
                    }

                    // Add new text to index
                    if let Some(text) = value.as_string() {
                        if index {
                            batch.ops.push(Operation::Index {
                                field: property.clone().into(),
                                key: text.serialize(),
                                set: true,
                            });
                        }
                        if tokenize {
                            for token in text.to_tokens() {
                                if !remove_tokens.remove(&token) {
                                    add_tokens.insert(token);
                                }
                            }
                        }
                    }

                    // Update tokens
                    for (token, set) in [(add_tokens, true), (remove_tokens, false)] {
                        for token in token {
                            batch.ops.push(Operation::hash(
                                &token,
                                HASH_EXACT,
                                property.clone().into(),
                                set,
                            ));
                        }
                    }
                }
                IndexAs::TextList { tokenize, index } => {
                    let mut add_tokens = HashSet::new();
                    let mut remove_tokens = HashSet::new();
                    let mut add_values = HashSet::new();
                    let mut remove_values = HashSet::new();

                    // Remove current text from index
                    if let Some(current_values) = current_value.as_list() {
                        for current_value in current_values {
                            if let Some(text) = current_value.as_string() {
                                if index {
                                    remove_values.insert(text);
                                }
                                if tokenize {
                                    remove_tokens.extend(text.to_tokens());
                                }
                            }
                        }
                    }

                    // Add new text to index
                    if let Some(values) = value.as_list() {
                        for value in values {
                            if let Some(text) = value.as_string() {
                                if index && !remove_values.remove(text) {
                                    add_values.insert(text);
                                }
                                if tokenize {
                                    for token in text.to_tokens() {
                                        if !remove_tokens.remove(&token) {
                                            add_tokens.insert(token);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Update index
                    for (values, set) in [(add_values, true), (remove_values, false)] {
                        for value in values {
                            batch.ops.push(Operation::Index {
                                field: property.clone().into(),
                                key: value.serialize(),
                                set,
                            });
                        }
                    }

                    // Update tokens
                    for (token, set) in [(add_tokens, true), (remove_tokens, false)] {
                        for token in token {
                            batch.ops.push(Operation::hash(
                                &token,
                                HASH_EXACT,
                                property.clone().into(),
                                set,
                            ));
                        }
                    }
                }
                index_as @ (IndexAs::Integer | IndexAs::LongInteger) => {
                    if let Some(current_value) = current_value.try_cast_uint() {
                        batch.ops.push(Operation::Index {
                            field: property.clone().into(),
                            key: current_value.into_index(index_as),
                            set: false,
                        });
                    }
                    if let Some(value) = value.try_cast_uint() {
                        batch.ops.push(Operation::Index {
                            field: property.clone().into(),
                            key: value.into_index(index_as),
                            set: true,
                        });
                    }
                }
                IndexAs::IntegerList => {
                    let mut add_values = HashSet::new();
                    let mut remove_values = HashSet::new();

                    if let Some(current_values) = current_value.as_list() {
                        for current_value in current_values {
                            if let Some(current_value) = current_value.try_cast_uint() {
                                remove_values.insert(current_value);
                            }
                        }
                    }
                    if let Some(values) = value.as_list() {
                        for value in values {
                            if let Some(value) = value.try_cast_uint() {
                                if !remove_values.remove(&value) {
                                    add_values.insert(value);
                                }
                            }
                        }
                    }

                    for (values, set) in [(add_values, true), (remove_values, false)] {
                        for value in values {
                            batch.ops.push(Operation::Index {
                                field: property.clone().into(),
                                key: (value as u32).serialize(),
                                set,
                            });
                        }
                    }
                }
                IndexAs::HasProperty => {
                    if current_value == &Value::Null {
                        batch.ops.push(Operation::Bitmap {
                            family: ().family(),
                            field: property.clone().into(),
                            key: vec![],
                            set: true,
                        });
                    } else if value == Value::Null {
                        batch.ops.push(Operation::Bitmap {
                            family: ().family(),
                            field: property.clone().into(),
                            key: vec![],
                            set: false,
                        });
                    }
                }
                IndexAs::Acl => {
                    match (current_value, &value) {
                        (Value::List(current_value), Value::List(value)) => {
                            // Remove deleted ACLs
                            for item in current_value.chunks_exact(2) {
                                if let Some(Value::Id(id)) = item.first() {
                                    if !value.contains(&Value::Id(*id)) {
                                        batch.ops.push(Operation::Acl {
                                            grant_account_id: id.document_id(),
                                            set: None,
                                        });
                                    }
                                }
                            }

                            // Update ACLs
                            for item in value.chunks_exact(2) {
                                if let (Some(Value::Id(id)), Some(Value::UnsignedInt(acl))) =
                                    (item.first(), item.last())
                                {
                                    let mut add_item = true;
                                    for current_item in current_value.chunks_exact(2) {
                                        if let (
                                            Some(Value::Id(current_id)),
                                            Some(Value::UnsignedInt(current_acl)),
                                        ) = (current_item.first(), current_item.last())
                                        {
                                            if id == current_id {
                                                if acl == current_acl {
                                                    add_item = false;
                                                }
                                                break;
                                            }
                                        }
                                    }
                                    if add_item {
                                        batch.ops.push(Operation::Acl {
                                            grant_account_id: id.document_id(),
                                            set: acl.serialize().into(),
                                        });
                                    }
                                }
                            }
                        }
                        (Value::Null, Value::List(values)) => {
                            // Add all ACLs
                            for item in values.chunks_exact(2) {
                                if let (Some(Value::Id(id)), Some(Value::UnsignedInt(acl))) =
                                    (item.first(), item.last())
                                {
                                    batch.ops.push(Operation::Acl {
                                        grant_account_id: id.document_id(),
                                        set: acl.serialize().into(),
                                    });
                                }
                            }
                        }
                        (Value::List(current_values), Value::Null) => {
                            // Remove all ACLs
                            for item in current_values.chunks_exact(2) {
                                if let Some(Value::Id(id)) = item.first() {
                                    batch.ops.push(Operation::Acl {
                                        grant_account_id: id.document_id(),
                                        set: None,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
                IndexAs::Quota => {
                    if let Some(current_value) = current_value.try_cast_uint() {
                        batch.quota(-(current_value as i64));
                    }
                    if let Some(value) = value.try_cast_uint() {
                        batch.quota(value as i64);
                    }
                }
                IndexAs::None => (),
            }
        }
        if value != Value::Null {
            current.set(property, value);
        } else {
            current.remove(&property);
        }
        has_changes = true;
    }

    if has_changes {
        batch.ops.push(Operation::Value {
            field: Property::Value.into(),
            family: 0,
            set: current.serialize().into(),
        });
    }
}

fn build_batch(
    batch: &mut BatchBuilder,
    index: &'static [IndexProperty],
    object: &Object<Value>,
    set: bool,
) {
    for item in index {
        match (object.get(&item.property), item.index_as) {
            (Value::Text(text), IndexAs::Text { tokenize, index }) => {
                if index {
                    batch.ops.push(Operation::Index {
                        field: (&item.property).into(),
                        key: text.serialize(),
                        set,
                    });
                }
                if tokenize {
                    for token in text.to_tokens() {
                        batch.ops.push(Operation::hash(
                            &token,
                            HASH_EXACT,
                            (&item.property).into(),
                            set,
                        ));
                    }
                }
            }
            (Value::List(values), IndexAs::TextList { tokenize, index }) => {
                let mut tokens = HashSet::new();
                let mut indexes = HashSet::new();
                for value in values {
                    if let Some(text) = value.as_string() {
                        if index {
                            indexes.insert(text);
                        }
                        if tokenize {
                            tokens.extend(text.to_tokens());
                        }
                    }
                }
                for text in indexes {
                    batch.ops.push(Operation::Index {
                        field: (&item.property).into(),
                        key: text.serialize(),
                        set,
                    });
                }
                for token in tokens {
                    batch.ops.push(Operation::hash(
                        &token,
                        HASH_EXACT,
                        (&item.property).into(),
                        set,
                    ));
                }
            }
            (Value::UnsignedInt(integer), IndexAs::Integer | IndexAs::LongInteger) => {
                batch.ops.push(Operation::Index {
                    field: (&item.property).into(),
                    key: integer.into_index(item.index_as),
                    set,
                });
            }
            (Value::Bool(boolean), IndexAs::Integer) => {
                batch.ops.push(Operation::Index {
                    field: (&item.property).into(),
                    key: (*boolean as u32).serialize(),
                    set,
                });
            }
            (Value::Id(id), IndexAs::Integer | IndexAs::LongInteger) => {
                batch.ops.push(Operation::Index {
                    field: (&item.property).into(),
                    key: id.into_index(item.index_as),
                    set,
                });
            }
            (Value::List(values), IndexAs::IntegerList) => {
                for value in values
                    .iter()
                    .map(|value| match value {
                        Value::UnsignedInt(integer) => *integer as u32,
                        Value::Id(id) => id.document_id(),
                        _ => unreachable!(),
                    })
                    .collect::<HashSet<_>>()
                {
                    batch.ops.push(Operation::Index {
                        field: (&item.property).into(),
                        key: value.into_index(item.index_as),
                        set,
                    });
                }
            }
            (Value::List(values), IndexAs::Acl) => {
                for item in values.chunks_exact(2) {
                    if let (Some(Value::Id(id)), Some(Value::UnsignedInt(acl))) =
                        (item.first(), item.last())
                    {
                        batch.ops.push(Operation::Acl {
                            grant_account_id: id.document_id(),
                            set: if set { acl.serialize().into() } else { None },
                        });
                    }
                }
            }
            (Value::UnsignedInt(bytes), IndexAs::Quota) => {
                batch.ops.push(Operation::UpdateQuota {
                    bytes: if set { *bytes as i64 } else { -(*bytes as i64) },
                });
            }
            (value, IndexAs::HasProperty) if value != &Value::Null => {
                batch.ops.push(Operation::Bitmap {
                    family: ().family(),
                    field: (&item.property).into(),
                    key: vec![],
                    set,
                });
            }

            _ => (),
        }
    }
}

impl IndexProperty {
    pub const fn new(property: Property) -> Self {
        Self {
            property,
            required: false,
            max_size: 0,
            index_as: IndexAs::None,
        }
    }

    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub const fn max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    pub const fn index_as(mut self, index_as: IndexAs) -> Self {
        self.index_as = index_as;
        self
    }
}

trait IntoIndex {
    fn into_index(self, index_as: IndexAs) -> Vec<u8>;
}

impl IntoIndex for &u64 {
    fn into_index(self, index_as: IndexAs) -> Vec<u8> {
        match index_as {
            IndexAs::Integer => (*self as u32).serialize(),
            IndexAs::LongInteger => self.serialize(),
            _ => unreachable!(),
        }
    }
}

impl IntoIndex for &u32 {
    fn into_index(self, index_as: IndexAs) -> Vec<u8> {
        match index_as {
            IndexAs::Integer | IndexAs::IntegerList => self.serialize(),
            _ => unreachable!("index as {index_as:?} not supported for u32"),
        }
    }
}

impl IntoIndex for &Id {
    fn into_index(self, index_as: IndexAs) -> Vec<u8> {
        match index_as {
            IndexAs::Integer => self.document_id().serialize(),
            IndexAs::LongInteger => self.id().serialize(),
            _ => unreachable!("index as {index_as:?} not supported for Id"),
        }
    }
}
