use ahash::AHashMap;

pub mod changes;
pub mod copy;
pub mod get;
pub mod import;
pub mod parse;
pub mod query;
pub mod query_changes;
pub mod search_snippet;
pub mod set;
pub mod validate;

#[inline(always)]
pub fn ahash_is_empty<K, V>(map: &AHashMap<K, V>) -> bool {
    map.is_empty()
}
