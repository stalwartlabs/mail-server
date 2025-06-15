/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::validate::{ValidateSieveScriptRequest, ValidateSieveScriptResponse},
};
use std::future::Future;

use crate::blob::download::BlobDownload;

pub trait SieveScriptValidate: Sync + Send {
    fn sieve_script_validate(
        &self,
        request: ValidateSieveScriptRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<ValidateSieveScriptResponse>> + Send;
}

impl SieveScriptValidate for Server {
    async fn sieve_script_validate(
        &self,
        request: ValidateSieveScriptRequest,
        access_token: &AccessToken,
    ) -> trc::Result<ValidateSieveScriptResponse> {
        Ok(ValidateSieveScriptResponse {
            account_id: request.account_id,
            error: match self
                .blob_download(&request.blob_id, access_token)
                .await?
                .map(|bytes| self.core.sieve.untrusted_compiler.compile(&bytes))
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
