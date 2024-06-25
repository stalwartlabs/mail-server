/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Display,
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(feature = "test_mode")]
pub static STS_TEST_POLICY: parking_lot::Mutex<Vec<u8>> = parking_lot::Mutex::new(Vec::new());

use common::config::smtp::resolver::Policy;
use mail_auth::{common::lru::DnsCache, mta_sts::MtaSts, report::tlsrpt::ResultType};

use crate::core::SMTP;

use super::{parse::ParsePolicy, Error};

#[allow(unused_variables)]
impl SMTP {
    pub async fn lookup_mta_sts_policy<'x>(
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
            .txt_lookup::<MtaSts>(format!("_mta-sts.{domain}."))
            .await
        {
            Ok(record) => record,
            Err(err) => {
                // Return the cached policy in case of failure
                return if let Some(value) = self.core.smtp.resolvers.cache.mta_sts.get(domain) {
                    Ok(value)
                } else {
                    Err(err.into())
                };
            }
        };

        // Check if the policy has been cached
        if let Some(value) = self.core.smtp.resolvers.cache.mta_sts.get(domain) {
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
            .get(&format!("https://mta-sts.{domain}/.well-known/mta-sts.txt"))
            .send()
            .await?
            .bytes()
            .await?;
        #[cfg(feature = "test_mode")]
        let bytes = STS_TEST_POLICY.lock().clone();

        // Parse policy
        let policy = Policy::parse(
            std::str::from_utf8(&bytes).map_err(|err| Error::InvalidPolicy(err.to_string()))?,
            record.id.clone(),
        )?;
        let valid_until = Instant::now()
            + Duration::from_secs(if (3600..31557600).contains(&policy.max_age) {
                policy.max_age
            } else {
                86400
            });

        Ok(self.core.smtp.resolvers.cache.mta_sts.insert(
            domain.to_string(),
            Arc::new(policy),
            valid_until,
        ))
    }

    #[cfg(feature = "test_mode")]
    pub fn policy_add<'x>(
        &self,
        key: impl mail_auth::common::resolver::IntoFqdn<'x>,
        value: Policy,
        valid_until: std::time::Instant,
    ) {
        self.core.smtp.resolvers.cache.mta_sts.insert(
            key.into_fqdn().into_owned(),
            Arc::new(value),
            valid_until,
        );
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
                } else if err.is_status()
                    & err
                        .status()
                        .map_or(false, |s| s == reqwest::StatusCode::NOT_FOUND)
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
