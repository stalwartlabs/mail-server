use std::{sync::Arc, time::Duration};

use api::session::BaseCapabilities;
use auth::{
    oauth::OAuthCode,
    rate_limit::{AnonymousLimiter, AuthenticatedLimiter, RemoteAddress},
    AclToken, AuthDatabase, SqlDatabase,
};
use jmap_proto::{
    error::method::MethodError,
    method::{
        query::{QueryRequest, QueryResponse},
        set::{SetRequest, SetResponse},
    },
    types::{collection::Collection, property::Property},
};
use mail_send::mail_auth::common::lru::{DnsCache, LruCache};
use services::state::{self, init_state_manager, spawn_state_manager};
use sqlx::{mysql::MySqlPoolOptions, postgres::PgPoolOptions, sqlite::SqlitePoolOptions};
use store::{
    fts::Language,
    parking_lot::Mutex,
    query::{sort::Pagination, Comparator, Filter, ResultSet, SortedResultSet},
    roaring::RoaringBitmap,
    write::{BatchBuilder, BitmapFamily},
    BitmapKey, Deserialize, Serialize, Store, ValueKey,
};
use tokio::sync::mpsc;
use utils::{config::Rate, failed, UnwrapFailure};

pub mod api;
pub mod auth;
pub mod blob;
pub mod changes;
pub mod email;
pub mod mailbox;
pub mod push;
pub mod services;
pub mod thread;

pub struct JMAP {
    pub store: Store,
    pub config: Config,
    pub sessions: LruCache<String, u32>,
    pub acl_tokens: LruCache<u32, Arc<AclToken>>,
    pub rate_limit_auth: LruCache<u32, Arc<Mutex<AuthenticatedLimiter>>>,
    pub rate_limit_unauth: LruCache<RemoteAddress, Arc<Mutex<AnonymousLimiter>>>,
    pub oauth_codes: LruCache<String, Arc<OAuthCode>>,
    pub auth_db: AuthDatabase,
    pub state_tx: mpsc::Sender<state::Event>,
}

pub struct Config {
    pub default_language: Language,
    pub query_max_results: usize,
    pub changes_max_results: usize,

    pub request_max_size: usize,
    pub request_max_calls: usize,
    pub request_max_concurrent: u64,
    pub request_max_concurrent_total: u64,

    pub get_max_objects: usize,
    pub set_max_objects: usize,

    pub upload_max_size: usize,
    pub upload_max_concurrent: usize,

    pub mailbox_max_depth: usize,
    pub mailbox_name_max_len: usize,
    pub mail_attachments_max_size: usize,
    pub mail_parse_max_items: usize,

    pub sieve_max_script_name: usize,
    pub sieve_max_scripts: usize,

    pub session_cache_ttl: Duration,
    pub rate_authenticated: Rate,
    pub rate_authenticate_req: Rate,
    pub rate_anonymous: Rate,
    pub rate_use_forwarded: bool,

    pub event_source_throttle: Duration,
    pub push_max_total: usize,

    pub oauth_key: String,
    pub oauth_expiry_user_code: u64,
    pub oauth_expiry_auth_code: u64,
    pub oauth_expiry_token: u64,
    pub oauth_expiry_refresh_token: u64,
    pub oauth_expiry_refresh_token_renew: u64,
    pub oauth_max_auth_attempts: u32,

    pub capabilities: BaseCapabilities,
}

pub const SUPERUSER_ID: u32 = 0;
pub const LONG_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24);

pub enum MaybeError {
    Temporary,
    Permanent(String),
}

impl JMAP {
    pub async fn init(config: &utils::config::Config) -> Arc<Self> {
        let auth_db = match config
            .value_require("jmap.auth.database.type")
            .failed("Invalid property")
        {
            "ldap" => AuthDatabase::Ldap,
            "sql" => {
                let address = config
                    .value_require("jmap.auth.database.address")
                    .failed("Invalid property");
                let max_connections = config
                    .property("jmap.auth.database.max-connections")
                    .failed("Invalid property")
                    .unwrap_or(10);
                let min_connections = config
                    .property("jmap.auth.database.min-connections")
                    .failed("Invalid property")
                    .unwrap_or(0);
                let idle_timeout = config
                    .property("jmap.auth.database.idle-timeout")
                    .failed("Invalid property");

                let db = if address.starts_with("postgres:") {
                    SqlDatabase::Postgres(
                        PgPoolOptions::new()
                            .max_connections(max_connections)
                            .min_connections(min_connections)
                            .idle_timeout(idle_timeout)
                            .connect_lazy(address)
                            .failed(&format!("Failed to create connection pool for {address:?}")),
                    )
                } else if address.starts_with("mysql:") {
                    SqlDatabase::MySql(
                        MySqlPoolOptions::new()
                            .max_connections(max_connections)
                            .min_connections(min_connections)
                            .idle_timeout(idle_timeout)
                            .connect_lazy(address)
                            .failed(&format!("Failed to create connection pool for {address:?}")),
                    )
                } else if address.starts_with("mssql:") {
                    todo!()
                    /*SqlDatabase::MsSql(
                        MssqlPoolOptions::new()
                            .max_connections(max_connections)
                            .min_connections(min_connections)
                            .idle_timeout(idle_timeout)
                            .connect_lazy(address)
                            .failed(&format!("Failed to create connection pool for {address:?}")),
                    )*/
                } else if address.starts_with("sqlite:") {
                    SqlDatabase::SqlLite(
                        SqlitePoolOptions::new()
                            .max_connections(max_connections)
                            .min_connections(min_connections)
                            .idle_timeout(idle_timeout)
                            .connect_lazy(address)
                            .failed(&format!("Failed to create connection pool for {address:?}")),
                    )
                } else {
                    failed(&format!("Invalid database address {address:?}"));
                };
                AuthDatabase::Sql {
                    db,
                    query_uid_by_login: config
                        .value_require("jmap.auth.database.query.uid-by-login")
                        .failed("Invalid property")
                        .to_string(),
                    query_login_by_uid: config
                        .value_require("jmap.auth.database.query.login-by-uid")
                        .failed("Invalid property")
                        .to_string(),
                    query_secret_by_uid: config
                        .value_require("jmap.auth.database.query.secret-by-uid")
                        .failed("Invalid property")
                        .to_string(),
                    query_gids_by_uid: config
                        .value_require("jmap.auth.database.query.gids-by-uid")
                        .failed("Invalid property")
                        .to_string(),
                }
            }
            _ => failed("Invalid auth database type"),
        };

        // Init state manager
        let (state_tx, state_rx) = init_state_manager();

        let jmap_server = Arc::new(JMAP {
            store: Store::open(config).await.failed("Unable to open database"),
            config: Config::new(config).failed("Invalid configuration file"),
            sessions: LruCache::with_capacity(
                config
                    .property("jmap.session.cache.size")
                    .failed("Invalid property")
                    .unwrap_or(100),
            ),
            acl_tokens: LruCache::with_capacity(
                config
                    .property("jmap.session.cache.size")
                    .failed("Invalid property")
                    .unwrap_or(100),
            ),
            rate_limit_auth: LruCache::with_capacity(
                config
                    .property("jmap.rate-limit.account.size")
                    .failed("Invalid property")
                    .unwrap_or(1024),
            ),
            rate_limit_unauth: LruCache::with_capacity(
                config
                    .property("jmap.rate-limit.anonymous.size")
                    .failed("Invalid property")
                    .unwrap_or(2048),
            ),
            oauth_codes: LruCache::with_capacity(
                config
                    .property("oauth.code.cache-size")
                    .failed("Invalid property")
                    .unwrap_or(128),
            ),
            auth_db,
            state_tx,
        });

        // Spawn state manager
        spawn_state_manager(jmap_server.clone(), config, state_rx);

        jmap_server
    }

    pub async fn assign_document_id(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> Result<u32, MethodError> {
        self.store
            .assign_document_id(account_id, collection)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "error",
                    context = "assign_document_id",
                    error = ?err,
                    "Failed to assign documentId.");
                MethodError::ServerPartialFail
            })
    }

    pub async fn get_property<U>(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        property: impl AsRef<Property>,
    ) -> Result<Option<U>, MethodError>
    where
        U: Deserialize + 'static,
    {
        let property = property.as_ref();
        match self
            .store
            .get_value::<U>(ValueKey::new(account_id, collection, document_id, property))
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                document_id = document_id,
                                property = ?property,
                                error = ?err,
                                "Failed to retrieve property");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn get_properties<U>(
        &self,
        account_id: u32,
        collection: Collection,
        document_ids: impl Iterator<Item = u32>,
        property: impl AsRef<Property>,
    ) -> Result<Vec<Option<U>>, MethodError>
    where
        U: Deserialize + 'static,
    {
        let property = property.as_ref();
        match self
            .store
            .get_values::<U>(
                document_ids
                    .map(|document_id| ValueKey::new(account_id, collection, document_id, property))
                    .collect(),
            )
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                property = ?property,
                                error = ?err,
                                "Failed to retrieve properties");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn get_term_index<T: Deserialize + 'static>(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> Result<Option<T>, MethodError> {
        match self
            .store
            .get_value::<T>(ValueKey {
                account_id,
                collection: collection.into(),
                document_id,
                family: u8::MAX,
                field: u8::MAX,
            })
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                document_id = document_id,
                                error = ?err,
                                "Failed to retrieve term index");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn get_document_ids(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> Result<Option<RoaringBitmap>, MethodError> {
        match self
            .store
            .get_bitmap(BitmapKey::document_ids(account_id, collection))
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                error = ?err,
                                "Failed to retrieve document ids bitmap");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn get_tag(
        &self,
        account_id: u32,
        collection: Collection,
        property: impl AsRef<Property>,
        value: impl BitmapFamily + Serialize,
    ) -> Result<Option<RoaringBitmap>, MethodError> {
        let property = property.as_ref();
        match self
            .store
            .get_bitmap(BitmapKey::value(account_id, collection, property, value))
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                property = ?property,
                                error = ?err,
                                "Failed to retrieve tag bitmap");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn prepare_set_response<T>(
        &self,
        request: &SetRequest<T>,
        collection: Collection,
    ) -> Result<SetResponse, MethodError> {
        Ok(
            SetResponse::from_request(request, self.config.set_max_objects)?.with_state(
                self.assert_state(
                    request.account_id.document_id(),
                    collection,
                    &request.if_in_state,
                )
                .await?,
            ),
        )
    }

    pub async fn filter(
        &self,
        account_id: u32,
        collection: Collection,
        filters: Vec<Filter>,
    ) -> Result<ResultSet, MethodError> {
        self.store
            .filter(account_id, collection, filters)
            .await
            .map_err(|err| {
                tracing::error!(event = "error",
                                context = "mailbox_set",
                                account_id = account_id,
                                collection = ?collection,
                                error = ?err,
                                "Failed to execute filter.");

                MethodError::ServerPartialFail
            })
    }

    pub async fn build_query_response<T>(
        &self,
        result_set: &ResultSet,
        request: &QueryRequest<T>,
    ) -> Result<(QueryResponse, Option<Pagination>), MethodError> {
        let total = result_set.results.len() as usize;
        let (limit_total, limit) = if let Some(limit) = request.limit {
            if limit > 0 {
                let limit = std::cmp::min(limit, self.config.query_max_results);
                (std::cmp::min(limit, total), limit)
            } else {
                (0, 0)
            }
        } else {
            (
                std::cmp::min(self.config.query_max_results, total),
                self.config.query_max_results,
            )
        };
        Ok((
            QueryResponse {
                account_id: request.account_id,
                query_state: self
                    .get_state(result_set.account_id, result_set.collection)
                    .await?,
                can_calculate_changes: true,
                position: 0,
                ids: vec![],
                total: if request.calculate_total.unwrap_or(false) {
                    Some(total)
                } else {
                    None
                },
                limit: if total > limit { Some(limit) } else { None },
            },
            if limit_total > 0 {
                Pagination::new(
                    limit_total,
                    request.position.unwrap_or(0),
                    request.anchor.map(|a| a.document_id()),
                    request.anchor_offset.unwrap_or(0),
                )
                .into()
            } else {
                None
            },
        ))
    }

    pub async fn sort(
        &self,
        result_set: ResultSet,
        comparators: Vec<Comparator>,
        paginate: Pagination,
        mut response: QueryResponse,
    ) -> Result<QueryResponse, MethodError> {
        // Sort results
        let collection = result_set.collection;
        let account_id = result_set.account_id;
        response.update_results(
            match self.store.sort(result_set, comparators, paginate).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::error!(event = "error",
                                context = "store",
                                account_id = account_id,
                                collection = ?collection,
                                error = ?err,
                                "Sort failed");
                    return Err(MethodError::ServerPartialFail);
                }
            },
        )?;

        Ok(response)
    }

    pub async fn write_batch(&self, batch: BatchBuilder) -> Result<(), MethodError> {
        self.store.write(batch.build()).await.map_err(|err| {
            tracing::error!(
            event = "error",
            context = "write_batch",
            error = ?err,
            "Failed to write batch.");
            MethodError::ServerPartialFail
        })
    }
}

trait UpdateResults: Sized {
    fn update_results(&mut self, sorted_results: SortedResultSet) -> Result<(), MethodError>;
}

impl UpdateResults for QueryResponse {
    fn update_results(&mut self, sorted_results: SortedResultSet) -> Result<(), MethodError> {
        // Prepare response
        if sorted_results.found_anchor {
            self.position = sorted_results.position;
            self.ids = sorted_results
                .ids
                .into_iter()
                .map(|id| id.into())
                .collect::<Vec<_>>();
            Ok(())
        } else {
            Err(MethodError::AnchorNotFound)
        }
    }
}
