use crate::error::{NVDDBError, Result};
use crate::models::Vendor;
use crate::schema::vendors;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};

#[derive(Insertable)]
#[diesel(table_name = vendors)]
pub struct CreateVendors {
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
}
pub struct QueryVendor {
  pub name: String,
}
impl Vendor {
  // 创建提供商
  pub fn create(conn: &mut MysqlConnection, args: &CreateVendors) -> Result<Self> {
    if let Err(err) = diesel::insert_into(vendors::table)
      .values(args)
      .execute(conn)
    {
      // 重复了，说明已经存在该提供商
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(NVDDBError::DieselError { source: err });
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
  pub fn query(conn: &mut MysqlConnection, name: &str) -> Result<Self> {
    Ok(
      vendors::dsl::vendors
        .filter(vendors::name.eq(name))
        .first::<Self>(conn)?,
    )
  }
}
