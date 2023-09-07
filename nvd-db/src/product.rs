use crate::error::{NVDDBError, Result};
use crate::models::{Product, Vendor};
use crate::schema::{products, vendors};
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
  pub total: i64,
}
// 产品查询参数
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryProduct {
  pub vendor_name: Option<String>,
  pub name: Option<String>,
  pub official: Option<u8>,
  pub limit: i64,
  pub offset: i64,
}

impl Product {
  // 创建产品
  pub fn create(conn: &mut MysqlConnection, args: &CreateProduct) -> Result<Self> {
    if let Err(err) = diesel::insert_into(products::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在该产品
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(NVDDBError::DieselError { source: err });
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
  pub fn query_by_id(conn: &mut MysqlConnection, args: &QueryProductById) -> Result<Self> {
    Ok(
      products::dsl::products
        .filter(products::vendor_id.eq(&args.vendor_id))
        .filter(products::name.eq(&args.name))
        .first::<Product>(conn)?,
    )
  }
  pub fn query_by_name(
    conn: &mut MysqlConnection,
    args: &QueryProductByVendorName,
  ) -> Result<Self> {
    let vendor_id: Vendor = vendors::table
      .filter(vendors::name.eq(&args.vendor_name))
      .first(conn)?;
    let product_id: Product = Product::belonging_to(&vendor_id)
      .filter(products::name.eq(&args.name))
      .first(conn)?;
    Ok(product_id)
  }
  pub fn query(conn: &mut MysqlConnection, args: &QueryProduct) -> Result<ProductCount> {
    let total = {
      let mut query = products::table.into_boxed();
      if let Some(vendor_name) = &args.vendor_name {
        let v = Vendor::query(conn,vendor_name)?;
        query = query.filter(products::vendor_id.eq(v.id));
      }
      if let Some(name) = &args.name {
        query = query.filter(products::name.eq(name));
      }
      if let Some(official) = &args.official {
        query = query.filter(products::official.eq(official));
      }
      // 统计查询全部，分页用
      query
        .select(diesel::dsl::count(products::id))
        .first::<i64>(conn)?
    };
    let result = {
      let query = {
        let mut query = products::table.into_boxed();
        if let Some(vendor_name) = &args.vendor_name {
          let v = Vendor::query(conn,vendor_name)?;
          query = query.filter(products::vendor_id.eq(v.id));
        }
        if let Some(name) = &args.name {
          query = query.filter(products::name.eq(name));
        }
        if let Some(official) = &args.official {
          query = query.filter(products::official.eq(official));
        }
        query
      };
      query
        .offset(args.offset)
        .limit(args.limit)
        .load::<Product>(conn)?
    };
    Ok(ProductCount { result, total })
  }
}
