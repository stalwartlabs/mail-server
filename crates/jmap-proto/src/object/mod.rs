pub mod email;
pub mod email_submission;
pub mod mailbox;
pub mod sieve;

use std::slice::Iter;

use store::{
    write::{IntoBitmap, Operation, ToBitmaps},
    Deserialize, Serialize,
};
use utils::{
    codec::leb128::{Leb128Iterator, Leb128Vec},
    map::vec_map::VecMap,
};

use crate::types::{
    acl::Acl, blob::BlobId, date::UTCDate, id::Id, keyword::Keyword, property::Property,
    type_state::TypeState, value::Value,
};

#[derive(Debug, Clone, Default, serde::Serialize, PartialEq, Eq)]
pub struct Object<T> {
    pub properties: VecMap<Property, T>,
}

impl Object<Value> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            properties: VecMap::with_capacity(capacity),
        }
    }

    pub fn set(&mut self, property: Property, value: impl Into<Value>) -> bool {
        self.properties.set(property, value.into())
    }

    pub fn append(&mut self, property: Property, value: impl Into<Value>) {
        self.properties.append(property, value.into());
    }

    pub fn with_property(mut self, property: Property, value: impl Into<Value>) -> Self {
        self.properties.append(property, value.into());
        self
    }

    pub fn remove(&mut self, property: &Property) -> Value {
        self.properties.remove(property).unwrap_or(Value::Null)
    }

    pub fn get(&self, property: &Property) -> &Value {
        self.properties.get(property).unwrap_or(&Value::Null)
    }
}

impl ToBitmaps for Value {
    fn to_bitmaps(&self, ops: &mut Vec<store::write::Operation>, field: u8, set: bool) {
        match self {
            Value::Text(text) => text.as_str().to_bitmaps(ops, field, set),
            Value::Keyword(keyword) => {
                let (key, family) = keyword.into_bitmap();
                ops.push(Operation::Bitmap {
                    family,
                    field,
                    key,
                    set,
                });
            }
            Value::UnsignedInt(int) => {
                let (key, family) = (*int as u32).into_bitmap();
                ops.push(Operation::Bitmap {
                    family,
                    field,
                    key,
                    set,
                });
            }
            Value::List(items) => {
                for item in items {
                    match item {
                        Value::Text(text) => text.as_str().to_bitmaps(ops, field, set),
                        Value::UnsignedInt(int) => {
                            let (key, family) = (*int as u32).into_bitmap();
                            ops.push(Operation::Bitmap {
                                family,
                                field,
                                key,
                                set,
                            });
                        }
                        Value::Keyword(keyword) => {
                            let (key, family) = keyword.into_bitmap();
                            ops.push(Operation::Bitmap {
                                family,
                                field,
                                key,
                                set,
                            })
                        }
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }
}

const TEXT: u8 = 0;
const UNSIGNED_INT: u8 = 1;
const BOOL_TRUE: u8 = 2;
const BOOL_FALSE: u8 = 3;
const ID: u8 = 4;
const DATE: u8 = 5;
const BLOB_ID: u8 = 6;
const KEYWORD: u8 = 7;
const TYPE_STATE: u8 = 8;
const ACL: u8 = 9;
const LIST: u8 = 10;
const OBJECT: u8 = 11;
const NULL: u8 = 12;

impl Serialize for Value {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);
        self.serialize_value(&mut buf);
        buf
    }
}

impl Deserialize for Value {
    fn deserialize(bytes: &[u8]) -> store::Result<Self> {
        Self::deserialize_value(&mut bytes.iter())
            .ok_or_else(|| store::Error::InternalError("Failed to deserialize value.".to_string()))
    }
}

impl Serialize for Object<Value> {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);
        self.serialize_into(&mut buf);
        buf
    }
}

impl Deserialize for Object<Value> {
    fn deserialize(bytes: &[u8]) -> store::Result<Self> {
        Object::deserialize_from(&mut bytes.iter())
            .ok_or_else(|| store::Error::InternalError("Failed to deserialize object.".to_string()))
    }
}

impl Object<Value> {
    fn serialize_into(self, buf: &mut Vec<u8>) {
        buf.push_leb128(self.properties.len());
        for (k, v) in self.properties {
            k.serialize_value(buf);
            v.serialize_value(buf);
        }
    }

    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Object<Value>> {
        let len = bytes.next_leb128()?;
        let mut properties = VecMap::with_capacity(len);
        for _ in 0..len {
            let key = Property::deserialize_value(bytes)?;
            let value = Value::deserialize_value(bytes)?;
            properties.append(key, value);
        }
        Some(Object { properties })
    }
}

pub trait SerializeValue {
    fn serialize_value(self, buf: &mut Vec<u8>);
}

pub trait DeserializeValue: Sized {
    fn deserialize_value(bytes: &mut Iter<'_, u8>) -> Option<Self>;
}

impl SerializeValue for Value {
    fn serialize_value(self, buf: &mut Vec<u8>) {
        match self {
            Value::Text(v) => {
                buf.push(TEXT);
                v.serialize_value(buf);
            }
            Value::UnsignedInt(v) => {
                buf.push(UNSIGNED_INT);
                v.serialize_value(buf);
            }
            Value::Bool(v) => {
                buf.push(if v { BOOL_TRUE } else { BOOL_FALSE });
            }
            Value::Id(v) => {
                buf.push(ID);
                v.id().serialize_value(buf);
            }
            Value::Date(v) => {
                buf.push(DATE);
                (v.timestamp() as u64).serialize_value(buf);
            }
            Value::BlobId(v) => {
                buf.push(BLOB_ID);
                v.serialize_value(buf);
            }
            Value::Keyword(v) => {
                buf.push(KEYWORD);
                v.serialize_value(buf);
            }
            Value::TypeState(v) => {
                buf.push(TYPE_STATE);
                v.serialize_value(buf);
            }
            Value::Acl(v) => {
                buf.push(ACL);
                v.serialize_value(buf);
            }
            Value::List(v) => {
                buf.push(LIST);
                buf.push_leb128(v.len());
                for i in v {
                    i.serialize_value(buf);
                }
            }
            Value::Object(v) => {
                buf.push(OBJECT);
                v.serialize_into(buf);
            }
            Value::Null => {
                buf.push(NULL);
            }
        }
    }
}

impl DeserializeValue for Value {
    fn deserialize_value(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match *bytes.next()? {
            TEXT => Some(Value::Text(String::deserialize_value(bytes)?)),
            UNSIGNED_INT => Some(Value::UnsignedInt(bytes.next_leb128()?)),
            BOOL_TRUE => Some(Value::Bool(true)),
            BOOL_FALSE => Some(Value::Bool(false)),
            ID => Some(Value::Id(Id::new(bytes.next_leb128()?))),
            DATE => Some(Value::Date(UTCDate::from_timestamp(
                bytes.next_leb128::<u64>()? as i64,
            ))),
            BLOB_ID => Some(Value::BlobId(BlobId::deserialize_value(bytes)?)),
            KEYWORD => Some(Value::Keyword(Keyword::deserialize_value(bytes)?)),
            TYPE_STATE => Some(Value::TypeState(TypeState::deserialize_value(bytes)?)),
            ACL => Some(Value::Acl(Acl::deserialize_value(bytes)?)),
            LIST => {
                let len = bytes.next_leb128()?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(Value::deserialize_value(bytes)?);
                }
                Some(Value::List(items))
            }
            OBJECT => Some(Value::Object(Object::deserialize_from(bytes)?)),
            NULL => Some(Value::Null),
            _ => None,
        }
    }
}

impl SerializeValue for String {
    fn serialize_value(self, buf: &mut Vec<u8>) {
        buf.push_leb128(self.len());
        if !self.is_empty() {
            buf.extend_from_slice(self.as_bytes());
        }
    }
}

impl DeserializeValue for String {
    fn deserialize_value(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let len: usize = bytes.next_leb128()?;
        let mut s = Vec::with_capacity(len);
        for _ in 0..len {
            s.push(*bytes.next()?);
        }
        String::from_utf8(s).ok()
    }
}

impl SerializeValue for u64 {
    fn serialize_value(self, buf: &mut Vec<u8>) {
        buf.push_leb128(self);
    }
}

impl DeserializeValue for u64 {
    fn deserialize_value(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}
