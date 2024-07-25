use std::{cmp::Ordering, net::IpAddr, vec::IntoIter};

use mail_auth::IpLookupStrategy;
use store::{Deserialize, Rows, Value};
use trc::AddContext;

use crate::Core;

use super::*;

impl Core {
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
                    .map(|v| v.into())
            }
            F_KEY_GET => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_lookup_store(store.as_ref(), session_id)
                    .key_get::<VariableWrapper>(key.into_owned().into_bytes())
                    .await
                    .map(|value| value.map(|v| v.into_inner()).unwrap_or_default())
                    .caused_by(trc::location!())
            }
            F_KEY_EXISTS => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_lookup_store(store.as_ref(), session_id)
                    .key_exists(key.into_owned().into_bytes())
                    .await
                    .caused_by(trc::location!())
                    .map(|v| v.into())
            }
            F_KEY_SET => {
                let store = params.next_as_string();
                let key = params.next_as_string();
                let value = params.next_as_string();

                self.get_lookup_store(store.as_ref(), session_id)
                    .key_set(
                        key.into_owned().into_bytes(),
                        value.into_owned().into_bytes(),
                        None,
                    )
                    .await
                    .map(|_| true)
                    .caused_by(trc::location!())
                    .map(|v| v.into())
            }
            F_COUNTER_INCR => {
                let store = params.next_as_string();
                let key = params.next_as_string();
                let value = params.next_as_integer();

                self.get_lookup_store(store.as_ref(), session_id)
                    .counter_incr(key.into_owned().into_bytes(), value, None, true)
                    .await
                    .map(Variable::Integer)
                    .caused_by(trc::location!())
            }
            F_COUNTER_GET => {
                let store = params.next_as_string();
                let key = params.next_as_string();

                self.get_lookup_store(store.as_ref(), session_id)
                    .counter_get(key.into_owned().into_bytes())
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
        let store = self.get_lookup_store(arguments.next_as_string().as_ref(), session_id);
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
            .map_or(false, |q| q.eq_ignore_ascii_case(b"SELECT"))
        {
            let mut rows = store
                .query::<Rows>(&query, arguments)
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
                .query::<usize>(&query, arguments)
                .await
                .caused_by(trc::location!())
                .map(|v| v.into())
        }
    }

    async fn dns_query<'x>(&self, mut arguments: FncParams<'x>) -> trc::Result<Variable<'x>> {
        let entry = arguments.next_as_string();
        let record_type = arguments.next_as_string();

        if record_type.eq_ignore_ascii_case("ip") {
            self.smtp
                .resolvers
                .dns
                .ip_lookup(entry.as_ref(), IpLookupStrategy::Ipv4thenIpv6, 10)
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .map(|ip| Variable::from(ip.to_string()))
                        .collect::<Vec<_>>()
                        .into()
                })
        } else if record_type.eq_ignore_ascii_case("mx") {
            self.smtp
                .resolvers
                .dns
                .mx_lookup(entry.as_ref())
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
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
                        .into()
                })
        } else if record_type.eq_ignore_ascii_case("txt") {
            self.smtp
                .resolvers
                .dns
                .txt_raw_lookup(entry.as_ref())
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| Variable::from(String::from_utf8(result).unwrap_or_default()))
        } else if record_type.eq_ignore_ascii_case("ptr") {
            self.smtp
                .resolvers
                .dns
                .ptr_lookup(entry.parse::<IpAddr>().map_err(|err| {
                    trc::EventType::Eval(trc::EvalEvent::Error)
                        .into_err()
                        .details("Failed to parse IP address")
                        .reason(err)
                })?)
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .map(|host| Variable::from(host.to_string()))
                        .collect::<Vec<_>>()
                        .into()
                })
        } else if record_type.eq_ignore_ascii_case("ipv4") {
            self.smtp
                .resolvers
                .dns
                .ipv4_lookup(entry.as_ref())
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .map(|ip| Variable::from(ip.to_string()))
                        .collect::<Vec<_>>()
                        .into()
                })
        } else if record_type.eq_ignore_ascii_case("ipv6") {
            self.smtp
                .resolvers
                .dns
                .ipv6_lookup(entry.as_ref())
                .await
                .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
                .map(|result| {
                    result
                        .iter()
                        .map(|ip| Variable::from(ip.to_string()))
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

    pub fn next_as_string(&mut self) -> Cow<'x, str> {
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
        String::deserialize(bytes).map(|v| VariableWrapper(Variable::String(v.into())))
    }
}

impl From<store::Value<'static>> for VariableWrapper {
    fn from(value: store::Value<'static>) -> Self {
        VariableWrapper(match value {
            Value::Integer(v) => Variable::Integer(v),
            Value::Bool(v) => Variable::Integer(v as i64),
            Value::Float(v) => Variable::Float(v),
            Value::Text(v) => Variable::String(v),
            Value::Blob(v) => Variable::String(match v {
                std::borrow::Cow::Borrowed(v) => String::from_utf8_lossy(v),
                std::borrow::Cow::Owned(v) => String::from_utf8_lossy(&v).into_owned().into(),
            }),
            Value::Null => Variable::String("".into()),
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
        Variable::String(v) => Value::Text(v),
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
        Value::Text(v) => Variable::String(v),
        Value::Blob(v) => Variable::String(
            String::from_utf8(v.into_owned())
                .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
                .into(),
        ),
        Value::Null => Variable::default(),
    }
}
