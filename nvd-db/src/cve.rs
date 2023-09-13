use crate::cve_product::ProductByName;
use crate::error::{NVDDBError, Result};
use crate::models::{Cve, CveProduct, Product, Vendor};
use crate::product::QueryProductById;
use crate::schema::{cve_product, cves, products};
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
  pub id: Option<String>,
  pub year: Option<i32>,
  pub official: Option<u8>,
  pub vendor: Option<String>,
  pub product: Option<String>,
  pub limit: i64,
  pub offset: i64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CveInfoCount {
  pub result: Vec<Cve>,
  pub total: i64,
}
impl Default for QueryCve {
  fn default() -> Self {
    QueryCve {
      id: None,
      year: None,
      official: None,
      vendor: None,
      product: None,
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
    Self::query_by_id(conn, &args.id)
  }
  // 查单个cve不联cvss表
  pub fn query_by_id(conn: &mut MysqlConnection, id: &str) -> Result<Self> {
    Ok(cves::dsl::cves.filter(cves::id.eq(id)).first::<Cve>(conn)?)
  }
  // 联表查cvss
  pub fn query_by_id_with_cvss(conn: &mut MysqlConnection, id: &str) -> Result<Cve> {
    let t = cves::dsl::cves.filter(cves::id.eq(id));
    let c = t.get_result::<Cve>(conn)?;
    Ok(c)
  }
  // 按照查询条件返回列表和总数
  pub fn query(conn: &mut MysqlConnection, args: &QueryCve) -> Result<CveInfoCount> {
    let total = {
      let mut query = cves::table.into_boxed();
      if let Some(id) = &args.id {
        query = query.filter(cves::id.eq(id));
      }
      if let Some(year) = &args.year {
        query = query.filter(cves::year.eq(year));
      }
      if let Some(official) = &args.official {
        query = query.filter(cves::official.eq(official));
      }
      // 根据供应商和产品查询CVE编号，和字段ID冲突
      if args.vendor.is_some() || args.product.is_some() {
        let cve_ids = CveProduct::query_cve_by_product(
          conn,
          &ProductByName {
            vendor: args.vendor.clone(),
            product: args.product.clone(),
          },
        )?;
        if !cve_ids.is_empty() {
          query = query.filter(cves::id.eq_any(cve_ids));
        }
      }
      // 统计查询全部，分页用
      query
        .select(diesel::dsl::count(cves::id))
        .first::<i64>(conn)?
    };

    let result = {
      let query = {
        let mut query = cves::table.into_boxed();
        if let Some(id) = &args.id {
          query = query.filter(cves::id.eq(id));
        }
        if let Some(year) = &args.year {
          query = query.filter(cves::year.eq(year));
        }
        if let Some(official) = &args.official {
          query = query.filter(cves::official.eq(official));
        }
        // 根据供应商和产品查询CVE编号，和字段ID冲突
        if args.vendor.is_some() || args.product.is_some() {
          let cve_ids = CveProduct::query_cve_by_product(
            conn,
            &ProductByName {
              vendor: args.vendor.clone(),
              product: args.product.clone(),
            },
          )?;
          if !cve_ids.is_empty() {
            query = query.filter(cves::id.eq_any(cve_ids));
          }
        }
        query
      };
      query
        .offset(args.offset)
        .limit(args.limit)
        .load::<Cve>(conn)?
    };
    Ok(CveInfoCount { result, total })
  }
}
