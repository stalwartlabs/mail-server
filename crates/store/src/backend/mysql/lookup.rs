/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use mysql_async::{prelude::Queryable, Params, Row};

use crate::{IntoRows, QueryResult, QueryType, Value};

use super::MysqlStore;

impl MysqlStore {
    pub(crate) async fn query<T: QueryResult>(
        &self,
        query: &str,
        params: Vec<Value<'_>>,
    ) -> crate::Result<T> {
        let mut conn = self.conn_pool.get_conn().await?;
        let s = conn.prep(query).await?;
        let params = Params::Positional(params.into_iter().map(Into::into).collect());

        match T::query_type() {
            QueryType::Execute => conn.exec_drop(s, params).await.map_or_else(
                |e| Err(e.into()),
                |_| Ok(T::from_exec(conn.affected_rows() as usize)),
            ),
            QueryType::Exists => conn
                .exec_first::<Row, _, _>(s, params)
                .await
                .map_or_else(|e| Err(e.into()), |r| Ok(T::from_exists(r.is_some()))),
            QueryType::QueryOne => conn
                .exec_first::<Row, _, _>(s, params)
                .await
                .map_or_else(|e| Err(e.into()), |r| Ok(T::from_query_one(r))),
            QueryType::QueryAll => conn
                .exec::<Row, _, _>(s, params)
                .await
                .map_or_else(|e| Err(e.into()), |r| Ok(T::from_query_all(r))),
        }
    }
}

impl From<crate::Value<'_>> for mysql_async::Value {
    fn from(value: crate::Value) -> Self {
        match value {
            crate::Value::Integer(i) => mysql_async::Value::Int(i),
            crate::Value::Bool(b) => mysql_async::Value::Int(b as i64),
            crate::Value::Float(f) => mysql_async::Value::Double(f),
            crate::Value::Text(t) => mysql_async::Value::Bytes(t.into_owned().into_bytes()),
            crate::Value::Blob(b) => mysql_async::Value::Bytes(b.into_owned()),
            crate::Value::Null => mysql_async::Value::NULL,
        }
    }
}

impl From<mysql_async::Value> for crate::Value<'static> {
    fn from(value: mysql_async::Value) -> Self {
        match value {
            mysql_async::Value::Int(i) => Self::Integer(i),
            mysql_async::Value::UInt(i) => Self::Integer(i as i64),
            mysql_async::Value::Double(f) => Self::Float(f),
            mysql_async::Value::Bytes(b) => String::from_utf8(b).map_or_else(
                |e| Self::Blob(e.into_bytes().into()),
                |s| Self::Text(s.into()),
            ),
            mysql_async::Value::NULL => Self::Null,
            mysql_async::Value::Float(f) => Self::Float(f as f64),
            mysql_async::Value::Date(_, _, _, _, _, _, _)
            | mysql_async::Value::Time(_, _, _, _, _, _) => Self::Text(value.as_sql(true).into()),
        }
    }
}

impl IntoRows for Vec<mysql_async::Row> {
    fn into_rows(self) -> crate::Rows {
        crate::Rows {
            rows: self
                .into_iter()
                .map(|r| crate::Row {
                    values: r
                        .unwrap_raw()
                        .into_iter()
                        .flatten()
                        .map(Into::into)
                        .collect(),
                })
                .collect(),
        }
    }

    fn into_named_rows(self) -> crate::NamedRows {
        crate::NamedRows {
            names: self
                .first()
                .map(|r| r.columns().iter().map(|c| c.name_str().into()).collect())
                .unwrap_or_default(),
            rows: self
                .into_iter()
                .map(|r| crate::Row {
                    values: r
                        .unwrap_raw()
                        .into_iter()
                        .flatten()
                        .map(Into::into)
                        .collect(),
                })
                .collect(),
        }
    }

    fn into_row(self) -> Option<crate::Row> {
        unreachable!()
    }
}

impl IntoRows for Option<mysql_async::Row> {
    fn into_row(self) -> Option<crate::Row> {
        self.map(|row| crate::Row {
            values: row
                .unwrap_raw()
                .into_iter()
                .flatten()
                .map(Into::into)
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
