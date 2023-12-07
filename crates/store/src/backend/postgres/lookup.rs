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

use crate::{QueryResult, QueryType};

use bytes::BytesMut;
use futures::{pin_mut, TryStreamExt};
use tokio_postgres::types::{FromSql, ToSql, Type};

use crate::IntoRows;

use super::PostgresStore;

impl PostgresStore {
    pub(crate) async fn query<T: QueryResult>(
        &self,
        query: &str,
        params_: Vec<crate::Value<'_>>,
    ) -> crate::Result<T> {
        let conn = self.conn_pool.get().await?;
        let s = conn.prepare_cached(query).await?;
        let params = params_
            .iter()
            .map(|v| v as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();

        match T::query_type() {
            QueryType::Execute => conn
                .execute(&s, params.as_slice())
                .await
                .map_or_else(|e| Err(e.into()), |r| Ok(T::from_exec(r as usize))),
            QueryType::Exists => {
                let rows = conn.query_raw(&s, params.into_iter()).await?;
                pin_mut!(rows);
                rows.try_next()
                    .await
                    .map_or_else(|e| Err(e.into()), |r| Ok(T::from_exists(r.is_some())))
            }
            QueryType::QueryOne => conn
                .query_opt(&s, params.as_slice())
                .await
                .map_or_else(|e| Err(e.into()), |r| Ok(T::from_query_one(r))),
            QueryType::QueryAll => conn
                .query(&s, params.as_slice())
                .await
                .map_or_else(|e| Err(e.into()), |r| Ok(T::from_query_all(r))),
        }
    }
}

impl ToSql for crate::Value<'_> {
    fn to_sql(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    where
        Self: Sized,
    {
        match self {
            crate::Value::Integer(v) => match *ty {
                Type::CHAR => (*v as i8).to_sql(ty, out),
                Type::INT2 => (*v as i16).to_sql(ty, out),
                Type::INT4 => (*v as i32).to_sql(ty, out),
                _ => v.to_sql(ty, out),
            },
            crate::Value::Bool(v) => v.to_sql(ty, out),
            crate::Value::Float(v) => {
                if matches!(ty, &Type::FLOAT4) {
                    (*v as f32).to_sql(ty, out)
                } else {
                    v.to_sql(ty, out)
                }
            }
            crate::Value::Text(v) => v.to_sql(ty, out),
            crate::Value::Blob(v) => v.to_sql(ty, out),
            crate::Value::Null => None::<String>.to_sql(ty, out),
        }
    }

    fn accepts(_: &tokio_postgres::types::Type) -> bool
    where
        Self: Sized,
    {
        true
    }

    fn to_sql_checked(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            crate::Value::Integer(v) => match *ty {
                Type::CHAR => (*v as i8).to_sql_checked(ty, out),
                Type::INT2 => (*v as i16).to_sql_checked(ty, out),
                Type::INT4 => (*v as i32).to_sql_checked(ty, out),
                _ => v.to_sql_checked(ty, out),
            },
            crate::Value::Bool(v) => v.to_sql_checked(ty, out),
            crate::Value::Float(v) => {
                if matches!(ty, &Type::FLOAT4) {
                    (*v as f32).to_sql_checked(ty, out)
                } else {
                    v.to_sql_checked(ty, out)
                }
            }
            crate::Value::Text(v) => v.to_sql_checked(ty, out),
            crate::Value::Blob(v) => v.to_sql_checked(ty, out),
            crate::Value::Null => None::<String>.to_sql_checked(ty, out),
        }
    }
}

impl IntoRows for Vec<tokio_postgres::Row> {
    fn into_rows(self) -> crate::Rows {
        crate::Rows {
            rows: self
                .into_iter()
                .map(|r| crate::Row {
                    values: (0..r.len())
                        .map(|idx| r.try_get(idx).unwrap_or(crate::Value::Null))
                        .collect(),
                })
                .collect(),
        }
    }

    fn into_named_rows(self) -> crate::NamedRows {
        crate::NamedRows {
            names: self
                .first()
                .map(|r| r.columns().iter().map(|c| c.name().to_string()).collect())
                .unwrap_or_default(),
            rows: self
                .into_iter()
                .map(|r| crate::Row {
                    values: (0..r.len())
                        .map(|idx| r.try_get(idx).unwrap_or(crate::Value::Null))
                        .collect(),
                })
                .collect(),
        }
    }

    fn into_row(self) -> Option<crate::Row> {
        unreachable!()
    }
}

impl IntoRows for Option<tokio_postgres::Row> {
    fn into_row(self) -> Option<crate::Row> {
        self.map(|row| crate::Row {
            values: (0..row.len())
                .map(|idx| row.try_get(idx).unwrap_or(crate::Value::Null))
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

impl FromSql<'_> for crate::Value<'static> {
    fn from_sql(
        ty: &tokio_postgres::types::Type,
        raw: &'_ [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        match ty {
            &Type::VARCHAR | &Type::TEXT | &Type::BPCHAR | &Type::NAME | &Type::UNKNOWN => {
                String::from_sql(ty, raw).map(|s| crate::Value::Text(s.into()))
            }
            &Type::BOOL => bool::from_sql(ty, raw).map(crate::Value::Bool),
            &Type::CHAR => i8::from_sql(ty, raw).map(|v| crate::Value::Integer(v as i64)),
            &Type::INT2 => i16::from_sql(ty, raw).map(|v| crate::Value::Integer(v as i64)),
            &Type::INT4 => i32::from_sql(ty, raw).map(|v| crate::Value::Integer(v as i64)),
            &Type::INT8 | &Type::OID => i64::from_sql(ty, raw).map(crate::Value::Integer),
            &Type::FLOAT4 | &Type::FLOAT8 => f64::from_sql(ty, raw).map(crate::Value::Float),
            ty if (ty.name() == "citext"
                || ty.name() == "ltree"
                || ty.name() == "lquery"
                || ty.name() == "ltxtquery") =>
            {
                String::from_sql(ty, raw).map(|s| crate::Value::Text(s.into()))
            }
            _ => Vec::<u8>::from_sql(ty, raw).map(|b| crate::Value::Blob(b.into())),
        }
    }

    fn accepts(_: &tokio_postgres::types::Type) -> bool {
        true
    }
}
