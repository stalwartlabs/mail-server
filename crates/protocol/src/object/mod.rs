pub mod email;
pub mod email_submission;
pub mod mailbox;
pub mod sieve;

use store::{
    write::{IntoBitmap, Operation, Tokenize},
    Serialize,
};
use utils::map::vec_map::VecMap;

use crate::types::{property::Property, value::Value};

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
}

impl Serialize for Value {
    fn serialize(self) -> Vec<u8> {
        todo!()
    }
}

impl Tokenize for Value {
    fn tokenize(&self, ops: &mut Vec<store::write::Operation>, field: u8, set: bool) {
        match self {
            Value::Text(text) => text.as_str().tokenize(ops, field, set),
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
                        Value::Text(text) => text.as_str().tokenize(ops, field, set),
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
