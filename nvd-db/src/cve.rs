use crate::error::{NVDDBError, Result};
use crate::models::{Cve, Cvss2, Cvss3};
use crate::schema::{cves, cvss2, cvss3};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
// 创建CVE
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
// 返回的CVE结构
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
// CVE查询参数
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryCve {
  pub id: Option<String>,
  pub year: Option<i32>,
  pub official: Option<u8>,
  pub limit: i64,
  pub offset: i64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CveInfoCount {
  pub result:Vec<CveInfo>,
  pub total: i64,
}
impl Default for QueryCve {
  fn default() -> Self {
    QueryCve{
      id: None,
      year: None,
      official: None,
      limit: 20,
      offset: 0,
    }
  }
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
    Self::query_by_id(
      conn,
      &args.id,
    )
  }
  // 查单个cve不联cvss表
  pub fn query_by_id(conn: &mut MysqlConnection, id: &str) -> Result<Self> {
    Ok(
      cves::dsl::cves
        .filter(cves::id.eq(id))
        .first::<Cve>(conn)?,
    )
  }
  // 联表查cvss
  pub fn query_by_id_with_cvss(conn: &mut MysqlConnection, id: &str) -> Result<CveInfo> {
    let t = cves::dsl::cves
      .left_join(cvss2::table)
      .left_join(cvss3::table)
      .filter(cves::id.eq(id));
    let (c, c2, c3) = t.get_result::<(Cve, Option<Cvss2>, Option<Cvss3>)>(conn)?;
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
  // 按照查询条件返回列表和总数
  pub fn query(conn:&mut MysqlConnection,args:&QueryCve)->Result<CveInfoCount>{
    let query = {
      let mut query = cves::table.
          left_join(cvss2::table)
          .left_join(cvss3::table)
          .into_boxed();
      if let Some(id) = &args.id {
        query = query.filter(cves::id.eq(id));
      }
      if let Some(year) = &args.year {
        query = query.filter(cves::year.eq(year));
      }
      if let Some(official) = &args.official {
        query = query.filter(cves::official.eq(official));
      }
      query
    };
    // 统计查询全部，分页用
    let total = query
        .select(diesel::dsl::count(cves::id))
        .first::<i64>(conn)?;
    let result = {
      let query = {
        let mut query = cves::table.
            left_join(cvss2::table)
            .left_join(cvss3::table)
            .into_boxed();
        if let Some(id) = &args.id {
          query = query.filter(cves::id.eq(id));
        }
        if let Some(year) = &args.year {
          query = query.filter(cves::year.eq(year));
        }
        if let Some(official) = &args.official {
          query = query.filter(cves::official.eq(official));
        }
        query
      };
      let cve_list =
          query
              .offset(args.offset)
              .limit(args.limit)
              .load::<(Cve, Option<Cvss2>, Option<Cvss3>)>(conn)?;
      cve_list.into_iter().map(|(cve_info,c2,c3)|{
        CveInfo {
          id: cve_info.id,
          year: cve_info.year,
          official: cve_info.official,
          assigner: cve_info.assigner,
          references: cve_info.references,
          description: cve_info.description,
          problem_type: cve_info.problem_type,
          cvss3: serde_json::json!(c3),
          cvss2: serde_json::json!(c2),
          configurations: cve_info.configurations,
          created_at: cve_info.created_at,
          updated_at: cve_info.updated_at,
        }
      }).collect::<Vec<_>>()
    };
    Ok(CveInfoCount{result,total})
  }
}
