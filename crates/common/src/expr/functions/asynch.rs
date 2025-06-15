/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cmp::Ordering, net::IpAddr, vec::IntoIter};

use compact_str::{CompactString, ToCompactString};
use directory::backend::RcptType;
use mail_auth::IpLookupStrategy;
use store::{Deserialize, Rows, Value, dispatch::lookup::KeyValue};
use trc::AddContext;

use crate::{Server, expr::StringCow};

use super::*;

impl Server {
    pub(crate) async fn eval_fnc<'x>(
        &self,
        fnc_id: u32,
        params: Vec<Variable<'x>>,
        session_id: u64,
    ) -> trc::Result<Variable<'x>> {
        let mut params = FncParams::new(params);

        match fnc_id {
            F_IS_LOCAL_DOMAIN => {
                let directory = params.next_as_string();
                let domain = params.next_as_string();

                self.get_directory_or_default(directory.as_ref(), session_id)
                    .is_local_domain(domain.as_ref())
                    .await
                    .caused_by(trc::location!())
                    .map(|v| v.into())
            }
            F_IS_LOCAL_ADDRESS => {
                let directory = params.next_as_string();
                let address = params.next_as_string();

                self.get_directory_or_default(directory.as_ref(), session_id)
                    .rcpt(address.as_ref())
                    .await
                    .caused_by(trc::location!())
                    .map(|v| (v != RcptType::Invalid).into())
            }
            F_KEY_GET => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_in_memory_store_or_default(store.as_str(), session_id)
                    .key_get::<VariableWrapper>(key.as_str())
                    .await
                    .map(|value| value.map(|v| v.into_inner()).unwrap_or_default())
                    .caused_by(trc::location!())
            }
            F_KEY_EXISTS => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_in_memory_store_or_default(store.as_str(), session_id)
                    .key_exists(key.as_str())
                    .await
                    .caused_by(trc::location!())
                    .map(|v| v.into())
            }
            F_KEY_SET => {
                let store = params.next_as_string();
                let key = params.next_as_string();
                let value = params.next_as_string();

                self.get_in_memory_store_or_default(store.as_ref(), session_id)
                    .key_set(KeyValue::new(
                        key.as_bytes().to_vec(),
                        value.as_bytes().to_vec(),
                    ))
                    .await
                    .map(|_| true)
                    .caused_by(trc::location!())
                    .map(|v| v.into())
            }
            F_COUNTER_INCR => {
                let store = params.next_as_string();
                let key = params.next_as_string();
                let value = params.next_as_integer();

                self.get_in_memory_store_or_default(store.as_ref(), session_id)
                    .counter_incr(KeyValue::new(key.into_owned(), value), true)
                    .await
                    .map(Variable::Integer)
                    .caused_by(trc::location!())
            }
            F_COUNTER_GET => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_in_memory_store_or_default(store.as_ref(), session_id)
                    .counter_get(key.as_bytes().to_vec())
                    .await
                    .map(Variable::Integer)
                    .caused_by(trc::location!())
            }
            F_DNS_QUERY => self.dns_query(params).await,
            F_SQL_QUERY => self.sql_query(params, session_id).await,
            _ => Ok(Variable::default()),
        }
    }

    async fn sql_query<'x>(
        &self,
        mut arguments: FncParams<'x>,
        session_id: u64,
    ) -> trc::Result<Variable<'x>> {
        let store = self.get_data_store(arguments.next_as_string().as_ref(), session_id);
        let query = arguments.next_as_string();

        if query.is_empty() {
            return Err(trc::EventType::Eval(trc::EvalEvent::Error)
                .into_err()
                .details("Empty query string"));
        }

        // Obtain arguments
        let arguments = match arguments.next() {
            Variable::Array(l) => l.into_iter().map(to_store_value).collect(),
            v => vec![to_store_value(v)],
        };

        // Run query
        if query
            .as_bytes()
            .get(..6)
            .is_some_and(|q| q.eq_ignore_ascii_case(b"SELECT"))
        {
            let mut rows = store
                .sql_query::<Rows>(query.as_str(), arguments)
                .await
                .caused_by(trc::location!())?;
            Ok(match rows.rows.len().cmp(&1) {
                Ordering::Equal => {
                    let mut row = rows.rows.pop().unwrap().values;
                    match row.len().cmp(&1) {
                        Ordering::Equal if !matches!(row.first(), Some(Value::Null)) => {
                            row.pop().map(into_variable).unwrap()
                        }
                        Ordering::Less => Variable::default(),
                        _ => {
                            Variable::Array(row.into_iter().map(into_variable).collect::<Vec<_>>())
                        }
                    }
                }
                Ordering::Less => Variable::default(),
                Ordering::Greater => rows
                    .rows
                    .into_iter()
                    .map(|r| {
                        Variable::Array(r.values.into_iter().map(into_variable).collect::<Vec<_>>())
                    })
                    .collect::<Vec<_>>()
                    .into(),
            })
        } else {
            store
                .sql_query::<usize>(query.as_str(), arguments)
                .await
                .caused_by(trc::location!())
                .map(|v| v.into())
        }
    }

    async fn dns_query<'x>(&self, mut arguments: FncParams<'x>) -> trc::Result<Variable<'x>> {
        let entry = arguments.next_as_string();
        let record_type = arguments.next_as_string();

        if record_type.as_str().eq_ignore_ascii_case("ip") {
            self.core
                .smtp
                .resolvers
                .dns
                .ip_lookup(
                    entry.as_ref(),
                    IpLookupStrategy::Ipv4thenIpv6,
                    10,
                    Some(&self.inner.cache.dns_ipv4),
                    Some(&self.inner.cache.dns_ipv6),
                )
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .map(|ip| Variable::from(ip.to_compact_string()))
                        .collect::<Vec<_>>()
                        .into()
                })
        } else if record_type.as_str().eq_ignore_ascii_case("mx") {
            self.core
                .smtp
                .resolvers
                .dns
                .mx_lookup(entry.as_str(), Some(&self.inner.cache.dns_mx))
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .flat_map(|mx| {
                            mx.exchanges.iter().map(|host| {
                                Variable::String(StringCow::Owned(
                                    host.strip_suffix('.')
                                        .unwrap_or(host.as_str())
                                        .to_compact_string(),
                                ))
                            })
                        })
                        .collect::<Vec<_>>()
                        .into()
                })
        } else if record_type.as_str().eq_ignore_ascii_case("txt") {
            self.core
                .smtp
                .resolvers
                .dns
                .txt_raw_lookup(entry.as_str())
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| Variable::from(CompactString::from_utf8(result).unwrap_or_default()))
        } else if record_type.as_str().eq_ignore_ascii_case("ptr") {
            self.core
                .smtp
                .resolvers
                .dns
                .ptr_lookup(
                    entry.as_str().parse::<IpAddr>().map_err(|err| {
                        trc::EventType::Eval(trc::EvalEvent::Error)
                            .into_err()
                            .details("Failed to parse IP address")
                            .reason(err)
                    })?,
                    Some(&self.inner.cache.dns_ptr),
                )
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .map(|host| Variable::from(host.to_compact_string()))
                        .collect::<Vec<_>>()
                        .into()
                })
        } else if record_type.as_str().eq_ignore_ascii_case("ipv4") {
            self.core
                .smtp
                .resolvers
                .dns
                .ipv4_lookup(entry.as_str(), Some(&self.inner.cache.dns_ipv4))
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .map(|ip| Variable::from(ip.to_compact_string()))
                        .collect::<Vec<_>>()
                        .into()
                })
        } else if record_type.as_str().eq_ignore_ascii_case("ipv6") {
            self.core
                .smtp
                .resolvers
                .dns
                .ipv6_lookup(entry.as_str(), Some(&self.inner.cache.dns_ipv6))
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .map(|ip| Variable::from(ip.to_compact_string()))
                        .collect::<Vec<_>>()
                        .into()
                })
        } else {
            Ok(Variable::default())
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

    pub fn next_as_string(&mut self) -> StringCow<'x> {
        self.params.next().unwrap().into_string()
    }

    pub fn next_as_integer(&mut self) -> i64 {
        self.params.next().unwrap().to_integer().unwrap_or_default()
    }

    pub fn next(&mut self) -> Variable<'x> {
        self.params.next().unwrap()
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
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(VariableWrapper(Variable::String(StringCow::Owned(
            CompactString::from_utf8_lossy(bytes),
        ))))
    }
}

impl From<store::Value<'static>> for VariableWrapper {
    fn from(value: store::Value<'static>) -> Self {
        VariableWrapper(match value {
            Value::Integer(v) => Variable::Integer(v),
            Value::Bool(v) => Variable::Integer(v as i64),
            Value::Float(v) => Variable::Float(v),
            Value::Text(v) => Variable::String(StringCow::Owned(v.into())),
            Value::Blob(v) => Variable::String(StringCow::Owned(match v {
                std::borrow::Cow::Borrowed(v) => CompactString::from_utf8_lossy(v),
                std::borrow::Cow::Owned(v) => CompactString::from_utf8_lossy(&v),
            })),
            Value::Null => Variable::String(StringCow::Borrowed("")),
        })
    }
}

impl VariableWrapper {
    pub fn into_inner(self) -> Variable<'static> {
        self.0
    }
}

fn to_store_value(value: Variable) -> Value {
    match value {
        Variable::String(v) => Value::Text(v.to_string().into()),
        Variable::Integer(v) => Value::Integer(v),
        Variable::Float(v) => Value::Float(v),
        v => Value::Text(v.to_string().into_owned().into()),
    }
}

fn into_variable(value: Value) -> Variable {
    match value {
        Value::Integer(v) => Variable::Integer(v),
        Value::Bool(v) => Variable::Integer(i64::from(v)),
        Value::Float(v) => Variable::Float(v),
        Value::Text(v) => Variable::String(v.into()),
        Value::Blob(v) => Variable::String(StringCow::Owned(CompactString::from_utf8_lossy(&v))),
        Value::Null => Variable::default(),
    }
}
