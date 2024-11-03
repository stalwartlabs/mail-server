/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use rqlite_rs::query::arguments::RqliteArgument;
use rqlite_rs::query::{Operation, RqliteQuery};

use crate::{IntoRows, QueryResult, QueryType, Value};

use super::{into_error, RqliteStore};

impl RqliteStore {
    pub(crate) async fn query<T: QueryResult>(
        &self,
        query: &str,
        params_: &[Value<'_>],
    ) -> trc::Result<T> {
        let conn = self.conn_pool.get().map_err(into_error)?;
        self.spawn_worker(move || {
            let params: Vec<RqliteArgument> =
                params_.iter().map(|v| (&v.to_owned()).into()).collect();

            let mut query = RqliteQuery {
                query: query.to_string(),
                args: params,
                op: Operation::Select,
            };

            match T::query_type() {
                QueryType::Execute => conn
                    .exec(query)
                    .await
                    .map_err(into_error)?
                    .map_or_else(|e| Err(into_error(e)), |r| Ok(T::from_exec(r))),
                QueryType::Exists => conn
                    .fetch(query)
                    .await
                    .map_err(into_error)?
                    .first()
                    .map(T::from_exists)
                    .map_err(into_error),
                QueryType::QueryOne => conn
                    .fetch(query)
                    .await
                    .map_err(into_error)?
                    .and_then(|mut rows| Ok(T::from_query_one(rows.first()?)))
                    .map_err(into_error),
                QueryType::QueryAll => Ok(T::from_query_all(
                    conn.fetch(query).await.map_err(into_error)?,
                )),
            }
        })
        .await
    }
}

impl From<&Value<'_>> for RqliteArgument {
    fn from(value: &Value<'_>) -> RqliteArgument {
        match value {
            Value::Integer(u) => RqliteArgument::I64(*u as i64),
            Value::Bool(b) => RqliteArgument::Bool(*b),
            Value::Float(f) => RqliteArgument::F64(*f as f64),
            Value::Text(s) => RqliteArgument::String(s.to_string()),
            Value::Blob(blob) => RqliteArgument::Blob(blob.to_vec()),
            Value::Null => RqliteArgument::Null,
        }
    }
}

/*
impl FromSql for Value<'static> {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Ok(match value {
            rusqlite::types::ValueRef::Null => Value::Null,
            rusqlite::types::ValueRef::Integer(v) => Value::Integer(v),
            rusqlite::types::ValueRef::Real(v) => Value::Float(v),
            rusqlite::types::ValueRef::Text(v) => {
                Value::Text(String::from_utf8_lossy(v).into_owned().into())
            }
            rusqlite::types::ValueRef::Blob(v) => Value::Blob(v.to_vec().into()),
        })
    }
} */

/*
impl IntoRows for Rows<'_> {
    fn into_rows(mut self) -> crate::Rows {
        let column_count = self.as_ref().map(|s| s.column_count()).unwrap_or_default();
        let mut rows = crate::Rows { rows: Vec::new() };

        while let Ok(Some(row)) = self.next() {
            rows.rows.push(crate::Row {
                values: (0..column_count)
                    .map(|idx| row.get::<_, Value>(idx).unwrap_or(Value::Null))
                    .collect(),
            });
        }

        rows
    }

    fn into_named_rows(mut self) -> crate::NamedRows {
        let (column_count, names) = self
            .as_ref()
            .map(|s| {
                (
                    s.column_count(),
                    s.column_names()
                        .into_iter()
                        .map(String::from)
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap_or((0, Vec::new()));

        let mut rows = crate::NamedRows {
            names,
            rows: Vec::new(),
        };

        while let Ok(Some(row)) = self.next() {
            rows.rows.push(crate::Row {
                values: (0..column_count)
                    .map(|idx| row.get::<_, Value>(idx).unwrap_or(Value::Null))
                    .collect(),
            });
        }

        rows
    }

    fn into_row(self) -> Option<crate::Row> {
        unreachable!()
    }
}
*/
/*
impl IntoRows for Option<&Row<'_>> {
    fn into_row(self) -> Option<crate::Row> {
        self.map(|row| crate::Row {
            values: (0..row.as_ref().column_count())
                .map(|idx| row.get::<_, Value>(idx).unwrap_or(Value::Null))
                .collect(),
        })
    }

    fn into_rows(self) -> crate::Rows {
        unreachable!()
    }

    fn into_named_rows(self) -> crate::NamedRows {
        unreachable!()
    }
}
*/
