use crate::error::{NVDDBError, Result};
use crate::models::{Product, Vendor};
use crate::schema::{products, vendors};
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};

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

pub struct DeleteProduct {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub name: String,
}
pub struct QueryProduct {
  pub vendor_id: Vec<u8>,
  pub name: String,
}
pub struct QueryProductByVendorName {
  pub vendor_name: String,
  pub name: String,
}
impl Product {
  // 按照供应商ID删除
  pub fn delete_by_vendor_id(conn: &mut MysqlConnection, args: &DeleteProduct) {
    let f = products::table.filter(products::vendor_id.eq(&args.vendor_id));
    diesel::delete(f).execute(conn).unwrap();
  }
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
    Self::query(
      conn,
      &QueryProduct {
        vendor_id: args.vendor_id.clone(),
        name: args.name.clone(),
      },
    )
  }
  pub fn query(conn: &mut MysqlConnection, args: &QueryProduct) -> Result<Self> {
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
}
