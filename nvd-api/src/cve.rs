use crate::cve_product::ProductByName;
use crate::error::{NVDDBError, Result};
use crate::models::{Cve, CveProduct};
use crate::schema::cves;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::DB;

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
  pub cvss3_vector: String,
  pub cvss3_score: f32,
  pub cvss2_vector: String,
  pub cvss2_score: f32,
  pub configurations: Value,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
// CVE查询参数
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryCve {
  // 精准CVE编号
  pub id: Option<String>,
  // 年份
  pub year: Option<i32>,
  // 是否为官方数据
  pub official: Option<u8>,
  // 供应商
  pub vendor: Option<String>,
  // 产品
  pub product: Option<String>,
  // 评分等级
  pub severity: Option<String>,
  // 分页每页
  pub limit: Option<i64>,
  // 分页偏移
  pub offset: Option<i64>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CveInfoCount {
  pub result: Vec<Cve>,
  pub total: i64,
}

impl QueryCve {
  // 查询参数过滤实现,免得写重复的过滤代码
  // https://github.com/diesel-rs/diesel/discussions/3468
  fn query<'a>(
    &'a self,
    conn: &mut MysqlConnection,
    mut query: cves::BoxedQuery<'a, DB>,
  ) -> Result<cves::BoxedQuery<'a, DB>> {
    if let Some(id) = &self.id {
      query = query.filter(cves::id.eq(id));
    }
    if let Some(year) = &self.year {
      query = query.filter(cves::year.eq(year));
    }
    if let Some(official) = &self.official {
      query = query.filter(cves::official.eq(official));
    }
    // 根据供应商和产品查询CVE编号，和字段ID冲突
    if self.vendor.is_some() || self.product.is_some() {
      let cve_ids = CveProduct::query_cve_by_product(
        conn,
        &ProductByName {
          vendor: self.vendor.clone(),
          product: self.product.clone(),
        },
      )?;
      if !cve_ids.is_empty() {
        query = query.filter(cves::id.eq_any(cve_ids));
      }
    }
    if let Some(severity) = &self.severity {
      match severity.to_lowercase().as_str() {
        "low" => {
          query = query.filter(
            cves::cvss3_score
              .between(0.1, 3.9)
              .or(cves::cvss2_score.between(0.1, 3.9)),
          );
        }
        "medium" => {
          query = query.filter(
            cves::cvss3_score
              .between(4.0, 6.9)
              .or(cves::cvss2_score.between(4.0, 6.9)),
          );
        }
        "high" => {
          query = query.filter(
            cves::cvss3_score
              .between(7.0, 8.9)
              .or(cves::cvss2_score.gt(7.0)),
          );
        }
        "critical" => {
          query = query.filter(cves::cvss3_score.gt(9.0));
        }
        _ => {}
      }
    }
    return Ok(query);
  }
  fn total(&self, conn: &mut MysqlConnection) -> Result<i64> {
    let query = self.query(conn, cves::table.into_boxed())?;
    // 统计查询全部，分页用
    Ok(query
      .select(diesel::dsl::count(cves::id))
      .first::<i64>(conn)?)
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
    Self::query_by_id(conn, &args.id)
  }
  // 查单个cve不联cvss表
  pub fn query_by_id(conn: &mut MysqlConnection, id: &str) -> Result<Self> {
    Ok(cves::dsl::cves.filter(cves::id.eq(id)).first::<Cve>(conn)?)
  }
  // 按照查询条件返回列表和总数
  pub fn query(conn: &mut MysqlConnection, args: &QueryCve) -> Result<CveInfoCount> {
    let total = args.total(conn)?;
    let result = {
      let query = args.query(conn, cves::table.into_boxed())?;
      // 限制最大分页为20,防止拒绝服务攻击
      query
        .offset(args.offset.unwrap_or(0))
        .limit(args.limit.map_or(20, |l| if l > 20 { 20 } else { l }))
        .load::<Cve>(conn)?
    };
    Ok(CveInfoCount { result, total })
  }
}
