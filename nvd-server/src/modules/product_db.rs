use crate::error::{DBError, DBResult};
use crate::modules::{Product, Vendor};
use crate::schema::{products, vendors};
use crate::DB;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::{Deserialize, Serialize};

#[derive(Insertable)]
#[diesel(table_name = products)]
pub struct CreateProduct {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub official: u8,
  pub part: String,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
}

pub struct QueryProductById {
  pub vendor_id: Vec<u8>,
  pub name: String,
}
pub struct QueryProductByVendorName {
  pub vendor_name: String,
  pub name: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ProductCount {
  pub result: Vec<Product>,
  // 分页每页
  pub size: i64,
  // 分页偏移
  pub page: i64,
  // 结果总数
  pub total: i64,
}
// 产品查询参数
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryProduct {
  pub vendor_name: Option<String>,
  pub name: Option<String>,
  pub part: Option<String>,
  pub official: Option<u8>,
  pub size: Option<i64>,
  pub page: Option<i64>,
}

impl QueryProduct {
  fn query<'a>(
    &'a self,
    conn: &mut MysqlConnection,
    mut query: products::BoxedQuery<'a, DB>,
  ) -> DBResult<products::BoxedQuery<'a, DB>> {
    if let Some(name) = &self.vendor_name {
      let v = Vendor::query_by_name(conn, name)?;
      query = query.filter(products::vendor_id.eq(v.id));
    }
    if let Some(part) = &self.part {
      query = query.filter(products::part.eq(part));
    }
    if let Some(name) = &self.name {
      let name = format!("{name}%");
      query = query.filter(products::name.like(name));
    }
    if let Some(official) = &self.official {
      query = query.filter(products::official.eq(official));
    }
    Ok(query)
  }
  fn total(&self, conn: &mut MysqlConnection) -> DBResult<i64> {
    let query = self.query(conn, products::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(
      query
        .select(diesel::dsl::count(products::id))
        .first::<i64>(conn)?,
    )
  }
}
impl Product {
  // 创建产品
  pub fn create(conn: &mut MysqlConnection, args: &CreateProduct) -> DBResult<Self> {
    if let Err(err) = diesel::insert_into(products::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在该产品
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(DBError::DieselError { source: err });
        }
      }
    }
    Self::query_by_id(
      conn,
      &QueryProductById {
        vendor_id: args.vendor_id.clone(),
        name: args.name.clone(),
      },
    )
  }
  // 查询产品从提供商的id
  pub fn query_by_id(conn: &mut MysqlConnection, args: &QueryProductById) -> DBResult<Self> {
    Ok(
      products::dsl::products
        .filter(products::vendor_id.eq(&args.vendor_id))
        .filter(products::name.eq(&args.name))
        .first::<Product>(conn)?,
    )
  }
  // 查询产品从提供商的名称
  pub fn query_by_vendor_name(
    conn: &mut MysqlConnection,
    args: &QueryProductByVendorName,
  ) -> DBResult<Self> {
    let v: Vendor = vendors::table
      .filter(vendors::name.eq(&args.vendor_name))
      .first(conn)?;
    let p: Product = Product::belonging_to(&v)
      .filter(products::name.eq(&args.name))
      .first(conn)?;
    Ok(p)
  }

  pub fn query(conn: &mut MysqlConnection, args: &QueryProduct) -> DBResult<ProductCount> {
    let total = args.total(conn)?;
    let page = args.page.unwrap_or(0).abs();
    let size = std::cmp::min(args.size.to_owned().unwrap_or(10).abs(), 10);
    let result = {
      let query = args.query(conn, products::table.into_boxed())?;
      query
        .offset(page * size)
        .limit(size)
        .order(products::name.asc())
        .load::<Product>(conn)?
    };
    Ok(ProductCount { result, size, page, total })
  }
}
