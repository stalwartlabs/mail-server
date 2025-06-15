/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, sync::Arc, time::Duration};

#[cfg(feature = "test_mode")]
pub static STS_TEST_POLICY: parking_lot::Mutex<Vec<u8>> = parking_lot::Mutex::new(Vec::new());

use common::{Server, config::smtp::resolver::Policy};
use mail_auth::{mta_sts::MtaSts, report::tlsrpt::ResultType};

use super::{Error, parse::ParsePolicy};

#[cfg(not(feature = "test_mode"))]
use utils::HttpLimitResponse;

#[cfg(not(feature = "test_mode"))]
const MAX_POLICY_SIZE: usize = 1024 * 1024;

pub trait MtaStsLookup: Sync + Send {
    fn lookup_mta_sts_policy(
        &self,
        domain: &str,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<Arc<Policy>, Error>> + Send;
}

#[allow(unused_variables)]
impl MtaStsLookup for Server {
    async fn lookup_mta_sts_policy(
        &self,
        domain: &str,
        timeout: Duration,
    ) -> Result<Arc<Policy>, Error> {
        // Lookup MTA-STS TXT record
        let record = match self
            .core
            .smtp
            .resolvers
            .dns
            .txt_lookup::<MtaSts>(
                format!("_mta-sts.{domain}."),
                Some(&self.inner.cache.dns_txt),
            )
            .await
        {
            Ok(record) => record,
            Err(err) => {
                // Return the cached policy in case of failure
                return if let Some(value) = self.inner.cache.dbs_mta_sts.get(domain) {
                    Ok(value)
                } else {
                    Err(err.into())
                };
            }
        };

        // Check if the policy has been cached
        if let Some(value) = self.inner.cache.dbs_mta_sts.get(domain) {
            if value.id == record.id {
                return Ok(value);
            }
        }

        // Fetch policy
        #[cfg(not(feature = "test_mode"))]
        let bytes = reqwest::Client::builder()
            .user_agent(common::USER_AGENT)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?
            .get(format!("https://mta-sts.{domain}/.well-known/mta-sts.txt"))
            .send()
            .await?
            .bytes_with_limit(MAX_POLICY_SIZE)
            .await?
            .ok_or_else(|| Error::InvalidPolicy("Policy too large".to_string()))?;
        #[cfg(feature = "test_mode")]
        let bytes = STS_TEST_POLICY.lock().clone();

        // Parse policy
        let policy = Arc::new(Policy::parse(
            std::str::from_utf8(&bytes).map_err(|err| Error::InvalidPolicy(err.to_string()))?,
            record.id.clone(),
        )?);

        self.inner.cache.dbs_mta_sts.insert(
            domain.to_string(),
            policy.clone(),
            Duration::from_secs(if (3600..31557600).contains(&policy.max_age) {
                policy.max_age
            } else {
                86400
            }),
        );

        Ok(policy)
    }
}

impl From<&Error> for ResultType {
    fn from(err: &Error) -> Self {
        match &err {
            Error::InvalidPolicy(_) => ResultType::StsPolicyInvalid,
            _ => ResultType::StsPolicyFetchError,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Dns(err) => match err {
                mail_auth::Error::DnsRecordNotFound(code) => {
                    write!(f, "Record not found: {code:?}")
                }
                mail_auth::Error::InvalidRecordType => {
                    f.write_str("Failed to parse MTA-STS DNS record.")
                }
                _ => write!(f, "DNS lookup error: {err}"),
            },
            Error::Http(err) => {
                if err.is_timeout() {
                    f.write_str("Timeout fetching policy.")
                } else if err.is_connect() {
                    f.write_str("Could not reach policy host.")
                } else if err.is_status() && (err.status() == Some(reqwest::StatusCode::NOT_FOUND))
                {
                    f.write_str("Policy not found.")
                } else {
                    f.write_str("Failed to fetch policy.")
                }
            }
            Error::InvalidPolicy(err) => write!(f, "Failed to parse policy: {err}"),
        }
    }
}

impl From<mail_auth::Error> for Error {
    fn from(value: mail_auth::Error) -> Self {
        Error::Dns(value)
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::Http(value)
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Error::InvalidPolicy(value)
    }
}
