use std::{borrow::Cow, sync::Arc, vec::IntoIter};

use directory::Directory;
use sieve::Sieve;
use store::{LookupKey, LookupStore, LookupValue};
use utils::{
    config::if_block::IfBlock,
    expr::{Expression, Variable},
};

use crate::{
    config::{ArcSealer, DkimSigner, RelayHost},
    scripts::plugins::lookup::VariableExists,
};

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
pub const F_KEY_GET: u32 = 1;
pub const F_KEY_EXISTS: u32 = 2;

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
            Err(_) => {
                tracing::warn!(
                    context = "eval_if",
                    event = "error",
                    property = if_block.key,
                    "Failed to convert value."
                );
                None
            }
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
            Err(_) => {
                tracing::warn!(
                    context = "eval_expr",
                    event = "error",
                    property = expr_id,
                    "Failed to convert value."
                );
                None
            }
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
            F_KEY_GET => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_lookup_store(store.as_ref())
                    .key_get::<String>(LookupKey::Key(key.into_owned().into_bytes()))
                    .await
                    .map(|value| {
                        if let LookupValue::Value { value, .. } = value {
                            Variable::from(value)
                        } else {
                            Variable::default()
                        }
                    })
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
                    .key_get::<VariableExists>(LookupKey::Key(key.into_owned().into_bytes()))
                    .await
                    .map(|value| matches!(value, LookupValue::Value { .. }))
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
