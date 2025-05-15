use common::Server;
use jmap_proto::types::collection::Collection;

async fn migrate_email(server: &Server, account_id: u32) -> trc::Result<()> {
    // Obtain email ids
    let document_ids = server
        .get_document_ids(account_id, Collection::Email)
        .await?
        .unwrap_or_default();

    //TODO remove tombstones

    Ok(())
}
