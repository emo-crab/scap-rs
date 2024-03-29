#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "db")]
use crate::schema::cves;
use crate::types::AnyValue;
use chrono::NaiveDateTime;
#[cfg(feature = "db")]
use diesel::{Identifiable, Insertable, Queryable};
use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi")]
use utoipa::{IntoParams, ToSchema};
#[cfg(feature = "yew")]
use yew::Properties;

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "db", derive(Queryable, Identifiable), diesel(table_name = cves))]
#[cfg_attr(feature = "yew", derive(Properties))]
#[derive(Default, Serialize, Clone, Deserialize, Debug, PartialEq)]
pub struct Cve {
  pub id: String,
  pub year: i32,
  pub assigner: String,
  pub description: AnyValue<Vec<nvd_cves::v4::Description>>,
  pub severity: String,
  pub metrics: AnyValue<nvd_cves::impact::ImpactMetrics>,
  pub weaknesses: AnyValue<Vec<nvd_cves::v4::Weaknesses>>,
  pub configurations: AnyValue<Vec<nvd_cves::v4::configurations::Node>>,
  pub references: AnyValue<Vec<nvd_cves::v4::Reference>>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

// 创建CVE
#[cfg_attr(feature = "db", derive(Insertable), diesel(table_name = cves))]
#[derive(Debug)]
pub struct CreateCve {
  pub id: String,
  pub year: i32,
  pub assigner: String,
  pub description: AnyValue<Vec<nvd_cves::v4::Description>>,
  pub severity: String,
  pub metrics: AnyValue<nvd_cves::impact::ImpactMetrics>,
  pub weaknesses: AnyValue<Vec<nvd_cves::v4::Weaknesses>>,
  pub configurations: AnyValue<Vec<nvd_cves::v4::configurations::Node>>,
  pub references: AnyValue<Vec<nvd_cves::v4::Reference>>,
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
