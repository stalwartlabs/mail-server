use jmap_proto::{
    error::{
        method::MethodError,
        set::{SetError, SetErrorType},
    },
    method::validate::{ValidateSieveScriptRequest, ValidateSieveScriptResponse},
};

use crate::{auth::AclToken, JMAP};

impl JMAP {
    pub async fn sieve_script_validate(
        &self,
        request: ValidateSieveScriptRequest,
        acl_token: &AclToken,
    ) -> Result<ValidateSieveScriptResponse, MethodError> {
        Ok(ValidateSieveScriptResponse {
            account_id: request.account_id,
            error: match self
                .blob_download(&request.blob_id, acl_token)
                .await?
                .map(|bytes| self.sieve_compiler.compile(&bytes))
            {
                Some(Ok(_)) => None,
                Some(Err(err)) => SetError::new(SetErrorType::InvalidScript)
                    .with_description(err.to_string())
                    .into(),
                None => SetError::new(SetErrorType::BlobNotFound).into(),
            },
        })
    }
}
