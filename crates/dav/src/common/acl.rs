use common::{Server, auth::AccessToken};
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use trc::AddContext;

use crate::DavError;

pub(crate) trait DavAclHandler: Sync + Send {
    fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        parent_id: Option<u32>,
        check_acls: Acl,
    ) -> impl Future<Output = crate::Result<u32>> + Send;
}

impl DavAclHandler for Server {
    async fn validate_and_map_parent_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: Collection,
        parent_id: Option<u32>,
        check_acls: Acl,
    ) -> crate::Result<u32> {
        match parent_id {
            Some(parent_id) => {
                if access_token.is_member(account_id)
                    || self
                        .has_access_to_document(
                            access_token,
                            account_id,
                            collection,
                            parent_id,
                            check_acls,
                        )
                        .await
                        .caused_by(trc::location!())?
                {
                    Ok(parent_id + 1)
                } else {
                    Err(DavError::Code(StatusCode::FORBIDDEN))
                }
            }
            None => {
                if access_token.is_member(account_id) {
                    Ok(0)
                } else {
                    Err(DavError::Code(StatusCode::FORBIDDEN))
                }
            }
        }
    }
}
