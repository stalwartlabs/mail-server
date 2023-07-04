use ahash::{AHashMap, AHashSet};

use crate::{DirectoryOptions, Principal};

pub mod config;
pub mod lookup;

#[derive(Default)]
pub struct MemoryDirectory {
    principals: AHashMap<String, Principal>,
    emails_to_names: AHashMap<String, Vec<EmailType>>,
    names_to_email: AHashMap<String, Vec<EmailType>>,
    domains: AHashSet<String>,
    opt: DirectoryOptions,
}

enum EmailType {
    Primary(String),
    Alias(String),
    List(String),
}
