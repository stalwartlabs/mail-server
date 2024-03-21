use std::{net::IpAddr, sync::Arc};

use ahash::AHashMap;
use config::{
    scripts::SieveCore,
    server::Server,
    smtp::{
        auth::{ArcSealer, DkimSigner},
        queue::RelayHost,
        SmtpConfig,
    },
    storage::Storage,
};
use directory::{Directory, Principal, QueryBy};
use listener::{acme::AcmeManager, blocked::BlockedIps, tls::Certificate};
use mail_send::Credentials;
use sieve::Sieve;
use store::LookupStore;

pub mod addresses;
pub mod config;
pub mod expr;
pub mod listener;

pub struct Core {
    pub storage: Storage,
    pub sieve: SieveCore,
    pub smtp: SmtpConfig,
    pub blocked_ips: BlockedIps,
}

pub struct ConfigBuilder {
    pub servers: Vec<Server>,
    pub certificates: AHashMap<String, Arc<Certificate>>,
    pub certificates_sni: AHashMap<String, Arc<Certificate>>,
    pub acme_managers: AHashMap<String, Arc<AcmeManager>>,
    pub core: Core,
}

pub enum AuthResult<T> {
    Success(T),
    Failure,
    Banned,
}

impl Core {
    pub fn get_directory(&self, name: &str) -> Option<&Arc<Directory>> {
        self.storage.directories.get(name)
    }

    pub fn get_directory_or_default(&self, name: &str) -> &Arc<Directory> {
        self.storage.directories.get(name).unwrap_or_else(|| {
            tracing::debug!(
                context = "get_directory",
                event = "error",
                directory = name,
                "Directory not found, using default."
            );

            &self.storage.directory
        })
    }

    pub fn get_lookup_store(&self, name: &str) -> &LookupStore {
        self.storage.lookups.get(name).unwrap_or_else(|| {
            tracing::debug!(
                context = "get_lookup_store",
                event = "error",
                directory = name,
                "Store not found, using default."
            );

            &self.storage.lookup
        })
    }

    pub fn get_arc_sealer(&self, name: &str) -> Option<&ArcSealer> {
        self.smtp
            .mail_auth
            .sealers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                tracing::warn!(
                    context = "get_arc_sealer",
                    event = "error",
                    name = name,
                    "Arc sealer not found."
                );

                None
            })
    }

    pub fn get_dkim_signer(&self, name: &str) -> Option<&DkimSigner> {
        self.smtp
            .mail_auth
            .signers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                tracing::warn!(
                    context = "get_dkim_signer",
                    event = "error",
                    name = name,
                    "DKIM signer not found."
                );

                None
            })
    }

    pub fn get_sieve_script(&self, name: &str) -> Option<&Arc<Sieve>> {
        self.sieve.scripts.get(name).or_else(|| {
            tracing::warn!(
                context = "get_sieve_script",
                event = "error",
                name = name,
                "Sieve script not found."
            );

            None
        })
    }

    pub fn get_relay_host(&self, name: &str) -> Option<&RelayHost> {
        self.smtp.queue.relay_hosts.get(name).or_else(|| {
            tracing::warn!(
                context = "get_relay_host",
                event = "error",
                name = name,
                "Remote host not found."
            );

            None
        })
    }

    pub async fn authenticate(
        &self,
        directory: &Directory,
        credentials: &Credentials<String>,
        remote_ip: IpAddr,
        return_member_of: bool,
    ) -> directory::Result<AuthResult<Principal<u32>>> {
        if let Some(principal) = directory
            .query(QueryBy::Credentials(credentials), return_member_of)
            .await?
        {
            Ok(AuthResult::Success(principal))
        } else if self.has_fail2ban() {
            let login = match credentials {
                Credentials::Plain { username, .. }
                | Credentials::XOauth2 { username, .. }
                | Credentials::OAuthBearer { token: username } => username,
            };
            if self.is_fail2banned(remote_ip, login.to_string()).await? {
                tracing::info!(
                    context = "directory",
                    event = "fail2ban",
                    remote_ip = ?remote_ip,
                    login = ?login,
                    "IP address blocked after too many failed login attempts",
                );

                Ok(AuthResult::Banned)
            } else {
                Ok(AuthResult::Failure)
            }
        } else {
            Ok(AuthResult::Failure)
        }
    }
}
