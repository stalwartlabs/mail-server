use api::session::BaseCapabilities;
use jmap_proto::{
    error::method::MethodError,
    types::{collection::Collection, property::Property},
};
use store::{
    fts::Language, roaring::RoaringBitmap, write::BitmapFamily, BitmapKey, Deserialize, Serialize,
    Store, ValueKey,
};
use utils::UnwrapFailure;

pub mod api;
pub mod blob;
pub mod changes;
pub mod email;
pub mod thread;

pub struct JMAP {
    pub store: Store,
    pub config: Config,
}

pub struct Config {
    pub default_language: Language,
    pub query_max_results: usize,

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

    pub sieve_max_script_name: usize,
    pub sieve_max_scripts: usize,

    pub capabilities: BaseCapabilities,
}

pub enum MaybeError {
    Temporary,
    Permanent(String),
}

impl JMAP {
    pub async fn new(config: &utils::config::Config) -> Self {
        JMAP {
            store: Store::open(config).await.failed("Unable to open database"),
            config: Config::new(config).failed("Invalid configuration file"),
        }
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
        document_ids: &[u32],
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
                    .iter()
                    .map(|document_id| {
                        ValueKey::new(account_id, collection, *document_id, property)
                    })
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
                                document_ids = ?document_ids,
                                property = ?property,
                                error = ?err,
                                "Failed to retrieve properties");
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
}
