use ahash::AHashMap;

use crate::Principal;

pub mod config;
pub mod lookup;

#[derive(Default)]
pub struct MemoryDirectory {
    principals: Vec<Principal>,
    names: AHashMap<String, u32>,
    emails_to_ids: AHashMap<String, Vec<EmailType<u32>>>,
    ids_to_email: AHashMap<u32, Vec<EmailType<String>>>,
}

enum EmailType<T> {
    Primary(T),
    Alias(T),
    List(T),
}
