use std::{collections::HashSet, sync::Arc, time::Instant};

use ahash::AHashMap;
use nlp::bayes::cache::BayesTokenCache;
use parking_lot::RwLock;
use sieve::{Compiler, Runtime, Sieve};
use utils::suffixlist::PublicSuffix;

use super::smtp::auth::DkimSigner;

pub struct SieveCore {
    pub untrusted_compiler: Compiler,
    pub untrusted_runtime: Runtime<()>,
    pub trusted_runtime: Runtime<SieveContext>,
    pub from_addr: String,
    pub from_name: String,
    pub return_path: String,
    pub sign: Vec<Arc<DkimSigner>>,
    pub scripts: AHashMap<String, Arc<Sieve>>,
}

#[derive(Default)]
pub struct SieveContext {
    pub psl: PublicSuffix,
    pub bayes_cache: BayesTokenCache,
    pub remote_lists: RemoteLists,
}

pub struct RemoteLists {
    pub lists: RwLock<AHashMap<String, RemoteList>>,
}

pub struct RemoteList {
    pub entries: HashSet<String>,
    pub expires: Instant,
}

impl Default for RemoteLists {
    fn default() -> Self {
        Self {
            lists: RwLock::new(AHashMap::new()),
        }
    }
}
