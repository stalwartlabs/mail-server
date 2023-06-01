use sqlx::{Any, Pool};

pub mod config;
pub mod lookup;

pub struct SqlDirectory {
    pool: Pool<Any>,
    mappings: SqlMappings,
}

#[derive(Debug)]
pub(crate) struct SqlMappings {
    query_login: String,
    query_name: String,
    query_id: String,
    query_members: String,
    query_recipients: String,
    query_emails: String,
    query_verify: String,
    query_expand: String,
    column_name: String,
    column_description: String,
    column_secret: String,
    column_id: String,
    column_quota: String,
    column_type: String,
}
