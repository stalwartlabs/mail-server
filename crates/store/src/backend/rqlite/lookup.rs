/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rusqlite::{types::FromSql, Row, Rows, ToSql};

use crate::{IntoRows, QueryResult, QueryType, Value};

use super::{into_error, SqliteStore};

impl SqliteStore {
    pub(crate) async fn query<T: QueryResult>(
        &self,
        query: &str,
        params_: &[Value<'_>],
    ) -> trc::Result<T> {
        let conn = self.conn_pool.get().map_err(into_error)?;
        self.spawn_worker(move || {
            let mut s = conn.prepare_cached(query).map_err(into_error)?;
            let params = params_
                .iter()
                .map(|v| v as &(dyn rusqlite::types::ToSql))
                .collect::<Vec<_>>();

            match T::query_type() {
                QueryType::Execute => s
                    .execute(params.as_slice())
                    .map_or_else(|e| Err(into_error(e)), |r| Ok(T::from_exec(r))),
                QueryType::Exists => s
                    .exists(params.as_slice())
                    .map(T::from_exists)
                    .map_err(into_error),
                QueryType::QueryOne => s
                    .query(params.as_slice())
                    .and_then(|mut rows| Ok(T::from_query_one(rows.next()?)))
                    .map_err(into_error),
                QueryType::QueryAll => Ok(T::from_query_all(
                    s.query(params.as_slice()).map_err(into_error)?,
                )),
            }
        })
        .await
    }
}

impl ToSql for Value<'_> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            Value::Integer(value) => value.to_sql(),
            Value::Bool(value) => value.to_sql(),
            Value::Float(value) => value.to_sql(),
            Value::Text(value) => value.to_sql(),
            Value::Blob(value) => value.to_sql(),
            Value::Null => Ok(rusqlite::types::ToSqlOutput::Owned(
                rusqlite::types::Value::Null,
            )),
        }
    }
}

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
}

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
