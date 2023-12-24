use crate::error::{DBError, DBResult};
use crate::modules::Vendor;
use crate::schema::vendors;
use crate::DB;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::{Deserialize, Serialize};
use super::ListResponse;
#[derive(Insertable)]
#[diesel(table_name = vendors)]
pub struct CreateVendors {
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryVendor {
  pub name: Option<String>,
  pub official: Option<u8>,
  pub size: Option<i64>,
  pub page: Option<i64>,
}

impl QueryVendor {
  fn query<'a>(
    &'a self,
    _conn: &mut MysqlConnection,
    mut query: vendors::BoxedQuery<'a, DB>,
  ) -> DBResult<vendors::BoxedQuery<'a, DB>> {
    if let Some(name) = &self.name {
      let name = format!("{name}%");
      query = query.filter(vendors::name.like(name));
    }
    if let Some(official) = &self.official {
      query = query.filter(vendors::official.eq(official));
    }
    Ok(query)
  }
  fn total(&self, conn: &mut MysqlConnection) -> DBResult<i64> {
    let query = self.query(conn, vendors::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(
      query
        .select(diesel::dsl::count(vendors::id))
        .first::<i64>(conn)?,
    )
  }
}
impl Vendor {
  // 创建提供商
  pub fn create(conn: &mut MysqlConnection, args: &CreateVendors) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(vendors::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在该提供商
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(DBError::DieselError { source: err });
        }
      }
    }
    Ok(
      // mysql 不支持 get_result，要再查一次得到插入结果
      vendors::dsl::vendors
        .filter(vendors::name.eq(&args.name))
        .first::<Vendor>(conn)?,
    )
  }
  // 查询提供商从名称
  pub fn query_by_name(conn: &mut MysqlConnection, name: &str) -> DBResult<Self> {
    Ok(
      vendors::dsl::vendors
        .filter(vendors::name.eq(name))
        .first::<Self>(conn)?,
    )
  }
  // 查询提供商从查询参数
  pub fn query(conn: &mut MysqlConnection, args: &QueryVendor) -> DBResult<ListResponse<Vendor>> {
    let total = args.total(conn)?;
    let page = args.page.unwrap_or(0).abs();
    let size = std::cmp::min(args.size.to_owned().unwrap_or(10).abs(), 10);
    let result = {
      let query = args.query(conn, vendors::table.into_boxed())?;
      query
        .offset(page * size)
        .limit(size)
        .order(vendors::name.asc())
        .load::<Vendor>(conn)?
    };
    Ok(ListResponse::new(result, total, page, size))
  }
}
