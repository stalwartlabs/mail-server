use std::{borrow::Cow, net::IpAddr, sync::Arc, vec::IntoIter};

use directory::Directory;
use mail_auth::IpLookupStrategy;
use sieve::Sieve;
use store::{Deserialize, LookupStore};
use utils::{
    config::if_block::IfBlock,
    expr::{Expression, Variable},
};

use crate::config::{ArcSealer, DkimSigner, RelayHost};

use super::{ResolveVariable, SMTP};

pub const V_RECIPIENT: u32 = 0;
pub const V_RECIPIENT_DOMAIN: u32 = 1;
pub const V_SENDER: u32 = 2;
pub const V_SENDER_DOMAIN: u32 = 3;
pub const V_MX: u32 = 4;
pub const V_HELO_DOMAIN: u32 = 5;
pub const V_AUTHENTICATED_AS: u32 = 6;
pub const V_LISTENER: u32 = 7;
pub const V_REMOTE_IP: u32 = 8;
pub const V_LOCAL_IP: u32 = 9;
pub const V_PRIORITY: u32 = 10;

pub const F_IS_LOCAL_DOMAIN: u32 = 0;
pub const F_IS_LOCAL_ADDRESS: u32 = 1;
pub const F_KEY_GET: u32 = 2;
pub const F_KEY_EXISTS: u32 = 3;
pub const F_DNS_QUERY: u32 = 4;

pub const VARIABLES_MAP: &[(&str, u32)] = &[
    ("rcpt", V_RECIPIENT),
    ("rcpt_domain", V_RECIPIENT_DOMAIN),
    ("sender", V_SENDER),
    ("sender_domain", V_SENDER_DOMAIN),
    ("mx", V_MX),
    ("helo_domain", V_HELO_DOMAIN),
    ("authenticated_as", V_AUTHENTICATED_AS),
    ("listener", V_LISTENER),
    ("remote_ip", V_REMOTE_IP),
    ("local_ip", V_LOCAL_IP),
    ("priority", V_PRIORITY),
];

pub const FUNCTIONS_MAP: &[(&str, u32, u32)] = &[
    ("is_local_domain", F_IS_LOCAL_DOMAIN, 2),
    ("key_get", F_KEY_GET, 2),
    ("key_exists", F_KEY_EXISTS, 2),
];

impl SMTP {
    pub async fn eval_if<R: for<'x> TryFrom<Variable<'x>>, V: ResolveVariable>(
        &self,
        if_block: &IfBlock,
        resolver: &V,
    ) -> Option<R> {
        if if_block.is_empty() {
            return None;
        }

        let result = if_block
            .eval(
                |var_id| resolver.resolve_variable(var_id),
                |fnc_id, params| async move { self.eval_fnc(fnc_id, params, &if_block.key).await },
            )
            .await;

        tracing::trace!(context = "eval_if",
                property = if_block.key,
                result = ?result,
        );

        match result.try_into() {
            Ok(value) => Some(value),
            Err(_) => None,
        }
    }

    pub async fn eval_expr<R: for<'x> TryFrom<Variable<'x>>, V: ResolveVariable>(
        &self,
        expr: &Expression,
        resolver: &V,
        expr_id: &str,
    ) -> Option<R> {
        if expr.is_empty() {
            return None;
        }

        let result = expr
            .eval(
                |var_id| resolver.resolve_variable(var_id),
                |fnc_id, params| async move { self.eval_fnc(fnc_id, params, expr_id).await },
                &mut Vec::new(),
            )
            .await;

        tracing::trace!(context = "eval_expr",
                property = expr_id,
                result = ?result,
        );

        match result.try_into() {
            Ok(value) => Some(value),
            Err(_) => None,
        }
    }

    async fn eval_fnc<'x>(
        &self,
        fnc_id: u32,
        params: Vec<Variable<'x>>,
        property: &str,
    ) -> Variable<'x> {
        let mut params = FncParams::new(params);

        match fnc_id {
            F_IS_LOCAL_DOMAIN => {
                let directory = params.next_as_string();
                let domain = params.next_as_string();

                self.get_directory_or_default(directory.as_ref())
                    .is_local_domain(domain.as_ref())
                    .await
                    .unwrap_or_else(|err| {
                        tracing::warn!(
                            context = "eval_if",
                            event = "error",
                            property = property,
                            error = ?err,
                            "Failed to check if domain is local."
                        );

                        false
                    })
                    .into()
            }
            F_IS_LOCAL_ADDRESS => {
                let directory = params.next_as_string();
                let address = params.next_as_string();

                self.get_directory_or_default(directory.as_ref())
                    .rcpt(address.as_ref())
                    .await
                    .unwrap_or_else(|err| {
                        tracing::warn!(
                            context = "eval_if",
                            event = "error",
                            property = property,
                            error = ?err,
                            "Failed to check if address is local."
                        );

                        false
                    })
                    .into()
            }
            F_KEY_GET => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_lookup_store(store.as_ref())
                    .key_get::<VariableWrapper>(key.into_owned().into_bytes())
                    .await
                    .map(|value| value.map(|v| v.into_inner()).unwrap_or_default())
                    .unwrap_or_else(|err| {
                        tracing::warn!(
                            context = "eval_if",
                            event = "error",
                            property = property,
                            error = ?err,
                            "Failed to get key."
                        );

                        Variable::default()
                    })
            }
            F_KEY_EXISTS => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_lookup_store(store.as_ref())
                    .key_exists(key.into_owned().into_bytes())
                    .await
                    .unwrap_or_else(|err| {
                        tracing::warn!(
                            context = "eval_if",
                            event = "error",
                            property = property,
                            error = ?err,
                            "Failed to get key."
                        );

                        false
                    })
                    .into()
            }
            F_DNS_QUERY => self.dns_query(params).await,
            _ => Variable::default(),
        }
    }

    pub fn get_directory(&self, name: &str) -> Option<&Arc<Directory>> {
        self.shared.directories.get(name)
    }

    pub fn get_directory_or_default(&self, name: &str) -> &Arc<Directory> {
        self.shared.directories.get(name).unwrap_or_else(|| {
            tracing::debug!(
                context = "get_directory",
                event = "error",
                directory = name,
                "Directory not found, using default."
            );

            &self.shared.default_directory
        })
    }

    pub fn get_lookup_store(&self, name: &str) -> &LookupStore {
        self.shared.lookup_stores.get(name).unwrap_or_else(|| {
            tracing::debug!(
                context = "get_lookup_store",
                event = "error",
                directory = name,
                "Store not found, using default."
            );

            &self.shared.default_lookup_store
        })
    }

    pub fn get_arc_sealer(&self, name: &str) -> Option<&ArcSealer> {
        self.shared
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
        self.shared
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
        self.shared.scripts.get(name).or_else(|| {
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
        self.shared.relay_hosts.get(name).or_else(|| {
            tracing::warn!(
                context = "get_relay_host",
                event = "error",
                name = name,
                "Remote host not found."
            );

            None
        })
    }

    async fn dns_query<'x>(&self, mut arguments: FncParams<'x>) -> Variable<'x> {
        let entry = arguments.next_as_string();
        let record_type = arguments.next_as_string();

        if record_type.eq_ignore_ascii_case("ip") {
            match self
                .resolvers
                .dns
                .ip_lookup(entry.as_ref(), IpLookupStrategy::Ipv4thenIpv6, 10)
                .await
            {
                Ok(result) => result
                    .iter()
                    .map(|ip| Variable::from(ip.to_string()))
                    .collect::<Vec<_>>()
                    .into(),
                Err(_) => Variable::default(),
            }
        } else if record_type.eq_ignore_ascii_case("mx") {
            match self.resolvers.dns.mx_lookup(entry.as_ref()).await {
                Ok(result) => result
                    .iter()
                    .flat_map(|mx| {
                        mx.exchanges.iter().map(|host| {
                            Variable::String(
                                host.strip_suffix('.')
                                    .unwrap_or(host.as_str())
                                    .to_string()
                                    .into(),
                            )
                        })
                    })
                    .collect::<Vec<_>>()
                    .into(),
                Err(_) => Variable::default(),
            }
        } else if record_type.eq_ignore_ascii_case("txt") {
            match self.resolvers.dns.txt_raw_lookup(entry.as_ref()).await {
                Ok(result) => Variable::from(String::from_utf8(result).unwrap_or_default()),
                Err(_) => Variable::default(),
            }
        } else if record_type.eq_ignore_ascii_case("ptr") {
            if let Ok(addr) = entry.parse::<IpAddr>() {
                match self.resolvers.dns.ptr_lookup(addr).await {
                    Ok(result) => result
                        .iter()
                        .map(|host| Variable::from(host.to_string()))
                        .collect::<Vec<_>>()
                        .into(),
                    Err(_) => Variable::default(),
                }
            } else {
                Variable::default()
            }
        } else if record_type.eq_ignore_ascii_case("ipv4") {
            match self.resolvers.dns.ipv4_lookup(entry.as_ref()).await {
                Ok(result) => result
                    .iter()
                    .map(|ip| Variable::from(ip.to_string()))
                    .collect::<Vec<_>>()
                    .into(),
                Err(_) => Variable::default(),
            }
        } else if record_type.eq_ignore_ascii_case("ipv6") {
            match self.resolvers.dns.ipv6_lookup(entry.as_ref()).await {
                Ok(result) => result
                    .iter()
                    .map(|ip| Variable::from(ip.to_string()))
                    .collect::<Vec<_>>()
                    .into(),
                Err(_) => Variable::default(),
            }
        } else {
            Variable::default()
        }
    }
}

struct FncParams<'x> {
    params: IntoIter<Variable<'x>>,
}

impl<'x> FncParams<'x> {
    pub fn new(params: Vec<Variable<'x>>) -> Self {
        Self {
            params: params.into_iter(),
        }
    }

    pub fn next_as_string(&mut self) -> Cow<'x, str> {
        self.params.next().unwrap().into_string()
    }
}

#[derive(Debug)]
struct VariableWrapper(Variable<'static>);

impl From<i64> for VariableWrapper {
    fn from(value: i64) -> Self {
        VariableWrapper(Variable::Integer(value))
    }
}

impl Deserialize for VariableWrapper {
    fn deserialize(bytes: &[u8]) -> store::Result<Self> {
        String::deserialize(bytes).map(|v| VariableWrapper(Variable::String(v.into())))
    }
}

impl From<store::Value<'static>> for VariableWrapper {
    fn from(value: store::Value<'static>) -> Self {
        VariableWrapper(value.into())
    }
}

impl VariableWrapper {
    pub fn into_inner(self) -> Variable<'static> {
        self.0
    }
}
