use super::ListResponse;
use crate::error::{DBError, DBResult};

use crate::modules::Cwe;
use crate::schema::cwes;
use crate::DB;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::{Deserialize, Serialize};
use utoipa::IntoParams;

#[derive(Insertable)]
#[diesel(table_name = cwes)]
pub struct CreateCwe {
  pub id: i32,
  pub name: String,
  pub description: String,
}

#[derive(Debug, Serialize, Deserialize, IntoParams)]
pub struct QueryCwe {
  pub id: Option<i32>,
  pub name: Option<String>,
  pub size: Option<i64>,
  pub page: Option<i64>,
}

impl QueryCwe {
  fn query<'a>(
    &'a self,
    _conn: &mut MysqlConnection,
    mut query: cwes::BoxedQuery<'a, DB>,
  ) -> DBResult<cwes::BoxedQuery<'a, DB>> {
    if let Some(name) = &self.name {
      let name = format!("%{name}%");
      query = query.filter(cwes::name.like(name));
    }
    if let Some(id) = &self.id {
      query = query.filter(cwes::id.eq(id));
    }
    Ok(query)
  }
  fn total(&self, conn: &mut MysqlConnection) -> DBResult<i64> {
    let query = self.query(conn, cwes::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(
      query
        .select(diesel::dsl::count(cwes::id))
        .first::<i64>(conn)?,
    )
  }
}

impl Cwe {
  // 创建弱点枚举
  pub fn create(conn: &mut MysqlConnection, args: &CreateCwe) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(cwes::table).values(args).execute(conn) {
      // 重复了，说明已经存在弱点
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(DBError::DieselError { source: err });
        }
      }
    }
    Ok(
      // mysql 不支持 get_result，要再查一次得到插入结果
      cwes::dsl::cwes
        .filter(cwes::name.eq(&args.name))
        .first::<Cwe>(conn)?,
    )
  }
  pub fn query_by_id(conn: &mut MysqlConnection, id: &i32) -> DBResult<Self> {
    Ok(
      cwes::dsl::cwes
        .filter(cwes::id.eq(id))
        .first::<Self>(conn)?,
    )
  }
  pub fn query(conn: &mut MysqlConnection, args: &QueryCwe) -> DBResult<ListResponse<Cwe>> {
    let total = args.total(conn)?;
    let page = args.page.unwrap_or(0).abs();
    let size = std::cmp::min(args.size.to_owned().unwrap_or(10).abs(), 10);
    let result = {
      let query = args.query(conn, cwes::table.into_boxed())?;
      query
        .offset(page)
        .limit(size)
        .order(cwes::name.asc())
        .load::<Cwe>(conn)?
    };
    Ok(ListResponse::new(result, total, page, size))
  }
}
