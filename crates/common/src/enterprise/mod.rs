/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

pub mod alerts;
pub mod config;
pub mod license;
pub mod llm;
pub mod undelete;

use std::{sync::Arc, time::Duration};

use ahash::{AHashMap, AHashSet};

use directory::{QueryBy, Type, backend::internal::lookup::DirectoryStore};
use license::LicenseKey;
use llm::AiApiConfig;
use mail_parser::DateTime;
use store::Store;
use trc::{AddContext, EventType, MetricType};
use utils::{HttpLimitResponse, config::cron::SimpleCron, template::Template};

use crate::{
    Core, Server, config::groupware::CalendarTemplateVariable, expr::Expression,
    manager::webadmin::Resource,
};

#[derive(Clone)]
pub struct Enterprise {
    pub license: LicenseKey,
    pub logo_url: Option<String>,
    pub undelete: Option<Undelete>,
    pub trace_store: Option<TraceStore>,
    pub metrics_store: Option<MetricStore>,
    pub metrics_alerts: Vec<MetricAlert>,
    pub ai_apis: AHashMap<String, Arc<AiApiConfig>>,
    pub spam_filter_llm: Option<SpamFilterLlmConfig>,
    pub template_calendar_alarm: Option<Template<CalendarTemplateVariable>>,
    pub template_calendar_invite: Option<Template<CalendarTemplateVariable>>,
}

#[derive(Debug, Clone)]
pub struct SpamFilterLlmConfig {
    pub model: Arc<AiApiConfig>,
    pub temperature: f64,
    pub prompt: String,
    pub separator: char,
    pub index_category: usize,
    pub index_confidence: Option<usize>,
    pub index_explanation: Option<usize>,
    pub categories: AHashSet<String>,
    pub confidence: AHashSet<String>,
}

#[derive(Clone)]
pub struct Undelete {
    pub retention: Duration,
}

#[derive(Clone)]
pub struct TraceStore {
    pub retention: Option<Duration>,
    pub store: Store,
}

#[derive(Clone)]
pub struct MetricStore {
    pub retention: Option<Duration>,
    pub store: Store,
    pub interval: SimpleCron,
}

#[derive(Clone, Debug)]
pub struct MetricAlert {
    pub id: String,
    pub condition: Expression,
    pub method: Vec<AlertMethod>,
}

#[derive(Clone, Debug)]
pub enum AlertMethod {
    Email {
        from_name: Option<String>,
        from_addr: String,
        to: Vec<String>,
        subject: AlertContent,
        body: AlertContent,
    },
    Event {
        message: Option<AlertContent>,
    },
}

#[derive(Clone, Debug)]
pub struct AlertContent(pub Vec<AlertContentToken>);

#[derive(Clone, Debug)]
pub enum AlertContentToken {
    Text(String),
    Metric(MetricType),
    Event(EventType),
}

impl Core {
    pub fn is_enterprise_edition(&self) -> bool {
        self.enterprise
            .as_ref()
            .is_some_and(|e| !e.license.is_expired())
    }
}

impl Server {
    // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
    // Any attempt to modify, bypass, or disable this license validation mechanism
    // constitutes a severe violation of the Stalwart Enterprise License Agreement.
    // Such actions may result in immediate termination of your license, legal action,
    // and substantial financial penalties. Stalwart Labs LLC actively monitors for
    // unauthorized modifications and will pursue all available legal remedies against
    // violators to the fullest extent of the law, including but not limited to claims
    // for copyright infringement, breach of contract, and fraud.

    #[inline]
    pub fn is_enterprise_edition(&self) -> bool {
        self.core.is_enterprise_edition()
    }

    pub fn licensed_accounts(&self) -> u32 {
        self.core
            .enterprise
            .as_ref()
            .map_or(0, |e| e.license.accounts)
    }

    pub fn log_license_details(&self) {
        if let Some(enterprise) = &self.core.enterprise {
            trc::event!(
                Server(trc::ServerEvent::Licensing),
                Details = "Stalwart Enterprise Edition license key is valid",
                Domain = enterprise.license.domain.clone(),
                Total = enterprise.license.accounts,
                ValidFrom =
                    DateTime::from_timestamp(enterprise.license.valid_from as i64).to_rfc3339(),
                ValidTo = DateTime::from_timestamp(enterprise.license.valid_to as i64).to_rfc3339(),
            );
        }
    }

    pub async fn logo_resource(&self, domain: &str) -> trc::Result<Option<Resource<Vec<u8>>>> {
        const MAX_IMAGE_SIZE: usize = 1024 * 1024;

        if self.is_enterprise_edition() {
            let domain = psl::domain_str(domain).unwrap_or(domain);
            let logo = { self.inner.data.logos.lock().get(domain).cloned() };

            if let Some(logo) = logo {
                Ok(logo)
            } else {
                // Try fetching the logo for the domain
                let logo_url = if let Some(mut principal) = self
                    .store()
                    .query(QueryBy::Name(domain), false)
                    .await
                    .caused_by(trc::location!())?
                    .filter(|p| p.typ() == Type::Domain)
                {
                    if let Some(logo) = principal.picture_mut().filter(|l| l.starts_with("http")) {
                        std::mem::take(logo).into()
                    } else if let Some(tenant_id) = principal.tenant {
                        if let Some(logo) = self
                            .store()
                            .query(QueryBy::Id(tenant_id), false)
                            .await
                            .caused_by(trc::location!())?
                            .and_then(|mut p| p.picture_mut().map(std::mem::take))
                            .filter(|l| l.starts_with("http"))
                        {
                            logo.clone().into()
                        } else {
                            self.default_logo_url()
                        }
                    } else {
                        self.default_logo_url()
                    }
                } else {
                    self.default_logo_url()
                };

                let mut logo = None;
                if let Some(logo_url) = logo_url {
                    let response = reqwest::get(logo_url.as_str()).await.map_err(|err| {
                        trc::ResourceEvent::DownloadExternal
                            .into_err()
                            .details("Failed to download logo")
                            .reason(err)
                    })?;

                    let content_type = response
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|ct| ct.to_str().ok())
                        .unwrap_or("image/svg+xml")
                        .to_string();

                    let contents = response
                        .bytes_with_limit(MAX_IMAGE_SIZE)
                        .await
                        .map_err(|err| {
                            trc::ResourceEvent::DownloadExternal
                                .into_err()
                                .details("Failed to download logo")
                                .reason(err)
                        })?
                        .ok_or_else(|| {
                            trc::ResourceEvent::DownloadExternal
                                .into_err()
                                .details("Download exceeded maximum size")
                        })?;

                    logo = Resource::new(content_type, contents).into();
                }

                self.inner
                    .data
                    .logos
                    .lock()
                    .insert(domain.to_string(), logo.clone());

                Ok(logo)
            }
        } else {
            Ok(None)
        }
    }

    fn default_logo_url(&self) -> Option<String> {
        self.core
            .enterprise
            .as_ref()
            .and_then(|e| e.logo_url.as_ref().map(|l| l.into()))
    }
}
