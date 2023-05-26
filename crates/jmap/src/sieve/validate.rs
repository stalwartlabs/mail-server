/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

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
