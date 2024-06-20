/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use std::{io::Write, ops::Range, time::Duration};

use s3::{
    creds::{error::CredentialsError, Credentials},
    error::S3Error,
    Bucket, Region,
};
use utils::{
    codec::base32_custom::Base32Writer,
    config::{utils::AsKey, Config},
};

pub struct S3Store {
    bucket: Bucket,
    prefix: Option<String>,
}

impl S3Store {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        // Obtain region and endpoint from config
        let prefix = prefix.as_key();
        let region = config.value_require((&prefix, "region"))?.to_string();
        let region = if let Some(endpoint) = config.value((&prefix, "endpoint")) {
            Region::Custom {
                region: region.to_string(),
                endpoint: endpoint.to_string(),
            }
        } else {
            region.parse().unwrap()
        };
        let credentials = Credentials::new(
            config.value((&prefix, "access-key")),
            config.value((&prefix, "secret-key")),
            config.value((&prefix, "security-token")),
            config.value((&prefix, "session-token")),
            config.value((&prefix, "profile")),
        )
        .map_err(|err| {
            config.new_build_error(
                prefix.as_str(),
                format!("Failed to create credentials: {err:?}"),
            )
        })
        .ok()?;
        let timeout = config
            .property_or_default::<Duration>((&prefix, "timeout"), "30s")
            .unwrap_or_else(|| Duration::from_secs(30));

        Some(S3Store {
            bucket: Bucket::new(
                config.value_require((&prefix, "bucket"))?,
                region,
                credentials,
            )
            .map_err(|err| {
                config.new_build_error(prefix.as_str(), format!("Failed to create bucket: {err:?}"))
            })
            .ok()?
            .with_path_style()
            .with_request_timeout(timeout)
            .map_err(|err| {
                config.new_build_error(prefix.as_str(), format!("Failed to create bucket: {err:?}"))
            })
            .ok()?,
            prefix: config.value((&prefix, "key-prefix")).map(|s| s.to_string()),
        })
    }

    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let path = self.build_key(key);
        let response = if range.start != 0 || range.end != usize::MAX {
            self.bucket
                .get_object_range(
                    path,
                    range.start as u64,
                    Some(range.end.saturating_sub(1) as u64),
                )
                .await
        } else {
            self.bucket.get_object(path).await
        };
        match response {
            Ok(response) if (200..300).contains(&response.status_code()) => {
                Ok(Some(response.to_vec()))
            }
            Ok(response) if response.status_code() == 404 => Ok(None),
            Ok(response) => Err(crate::Error::InternalError(format!(
                "S3 error code {}: {}",
                response.status_code(),
                String::from_utf8_lossy(response.as_slice())
            ))),
            Err(err) => Err(err.into()),
        }
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        match self.bucket.put_object(self.build_key(key), data).await {
            Ok(response) if (200..300).contains(&response.status_code()) => Ok(()),
            Ok(response) => Err(crate::Error::InternalError(format!(
                "S3 error code {}: {}",
                response.status_code(),
                String::from_utf8_lossy(response.as_slice())
            ))),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        self.bucket
            .delete_object(self.build_key(key))
            .await
            .map(|response| (200..300).contains(&response.status_code()))
            .map_err(|e| e.into())
    }

    fn build_key(&self, key: &[u8]) -> String {
        if let Some(prefix) = &self.prefix {
            let mut writer =
                Base32Writer::with_raw_capacity(prefix.len() + ((key.len() + 3) / 4 * 5));
            writer.push_string(prefix);
            writer.write_all(key).unwrap();
            writer.finalize()
        } else {
            Base32Writer::from_bytes(key).finalize()
        }
    }
}

impl From<S3Error> for crate::Error {
    fn from(err: S3Error) -> Self {
        Self::InternalError(format!("S3 error: {}", err))
    }
}

impl From<CredentialsError> for crate::Error {
    fn from(err: CredentialsError) -> Self {
        Self::InternalError(format!("S3 Credentials error: {}", err))
    }
}
