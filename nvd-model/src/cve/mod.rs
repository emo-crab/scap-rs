#[cfg(feature = "db")]
pub mod db;
#[cfg(feature = "db")]
use crate::schema::cves;
use chrono::NaiveDateTime;
#[cfg(feature = "db")]
use diesel::{Identifiable, Insertable, Queryable};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "openapi")]
use utoipa::{IntoParams, ToSchema};
#[cfg(feature = "yew")]
use yew::Properties;

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "db", derive(Queryable,Identifiable),diesel(table_name = cves))]
#[cfg_attr(feature = "yew", derive(Properties))]
#[derive(Default, Serialize, Clone, Deserialize, Debug, PartialEq)]
pub struct Cve {
  pub id: String,
  pub year: i32,
  pub assigner: String,
  #[cfg(all(feature = "db", not(feature = "yew")))]
  pub description: Value,
  #[cfg(all(feature = "yew", not(feature = "db")))]
  pub description: Vec<nvd_cves::v4::Description>,
  pub severity: String,
  #[cfg(all(feature = "db", not(feature = "yew")))]
  pub metrics: Value,
  #[cfg(all(feature = "db", not(feature = "yew")))]
  pub weaknesses: Value,
  #[cfg(all(feature = "db", not(feature = "yew")))]
  pub configurations: Value,
  #[cfg(all(feature = "db", not(feature = "yew")))]
  pub references: Value,
  #[cfg(all(feature = "yew", not(feature = "db")))]
  pub metrics: nvd_cves::impact::ImpactMetrics,
  #[cfg(all(feature = "yew", not(feature = "db")))]
  pub weaknesses: Vec<nvd_cves::v4::Weaknesses>,
  #[cfg(all(feature = "yew", not(feature = "db")))]
  pub configurations: Vec<nvd_cves::v4::configurations::Node>,
  #[cfg(all(feature = "yew", not(feature = "db")))]
  pub references: Vec<nvd_cves::v4::Reference>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
// 创建CVE
#[cfg_attr(feature = "db", derive(Insertable),diesel(table_name = cves))]
#[derive(Debug)]
pub struct CreateCve {
  pub id: String,
  pub year: i32,
  pub assigner: String,
  pub description: Value,
  pub severity: String,
  pub metrics: Value,
  pub weaknesses: Value,
  pub configurations: Value,
  pub references: Value,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
// CVE查询参数
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "yew", derive(Properties))]
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
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
  pub size: Option<i64>,
  // 分页偏移
  pub page: Option<i64>,
}
