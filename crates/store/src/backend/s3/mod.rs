/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
