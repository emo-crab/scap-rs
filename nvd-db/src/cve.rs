use crate::error::{NVDDBError, Result};
use crate::models::Cve;
use crate::schema::cves;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};

use serde_json::Value;

#[derive(Debug, Insertable)]
#[diesel(table_name = cves)]
pub struct CreateCve {
  pub id: String,
  pub year: i32,
  pub official: u8,
  pub assigner: String,
  pub references: Value,
  pub description: Value,
  pub problem_type: Value,
  pub cvss3_id: Option<Vec<u8>>,
  pub cvss2_id: Option<Vec<u8>>,
  pub configurations: Value,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

pub struct QueryCve {
  pub id: String,
  pub year: Option<i32>,
  pub official: Option<u8>,
}
impl Cve {
  // 创建CVE
  pub fn create(conn: &mut MysqlConnection, args: &CreateCve) -> Result<Self> {
    if let Err(err) = diesel::insert_into(cves::table).values(args).execute(conn) {
      // 重复了，说明已经存在CVE
      match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {}
        _ => {
          return Err(NVDDBError::DieselError { source: err });
        }
      }
    }
    // mysql 不支持 get_result，要再查一次得到插入结果
    Self::query(
      conn,
      &QueryCve {
        id: args.id.clone(),
        year: None,
        official: None,
      },
    )
  }
  pub fn query(conn: &mut MysqlConnection, args: &QueryCve) -> Result<Self> {
    Ok(
      cves::dsl::cves
        .filter(cves::id.eq(&args.id))
        .first::<Cve>(conn)?,
    )
  }
}
