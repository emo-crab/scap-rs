use crate::error::{NVDDBError, Result};
use crate::models::{Cve, Cvss2, Cvss3};
use crate::schema::{cves, cvss2, cvss3};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Serialize, Deserialize)]
pub struct CveInfo {
  pub id: String,
  pub year: i32,
  pub official: u8,
  pub assigner: String,
  pub references: Value,
  pub description: Value,
  pub problem_type: Value,
  pub cvss3: Value,
  pub cvss2: Value,
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
  pub fn query_with_cvss(conn: &mut MysqlConnection, args: &QueryCve) -> Result<CveInfo> {
    let t = cves::dsl::cves
      .inner_join(cvss2::table)
      .inner_join(cvss3::table)
      .filter(cves::id.eq(&args.id));
    let (c, c2, c3) = t.get_result::<(Cve, Cvss2, Cvss3)>(conn)?;
    println!("{:?}", c2);
    println!("{:?}", c3);
    Ok(CveInfo {
      id: c.id,
      year: c.year,
      official: c.official,
      assigner: c.assigner,
      references: c.references,
      description: c.description,
      problem_type: c.problem_type,
      cvss3: serde_json::json!(c3),
      cvss2: serde_json::json!(c2),
      configurations: c.configurations,
      created_at: c.created_at,
      updated_at: c.updated_at,
    })
  }
}
