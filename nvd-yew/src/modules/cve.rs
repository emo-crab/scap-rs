use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use yew::prelude::*;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct Cve {
  pub id: String,
  pub year: i32,
  pub assigner: String,
  pub description: Vec<cve::v4::Description>,
  pub severity: String,
  pub metrics: cve::impact::ImpactMetrics,
  pub weaknesses: Vec<cve::v4::Weaknesses>,
  pub configurations: Vec<cve::v4::configurations::Node>,
  pub references: Vec<cve::v4::Reference>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct CveInfoList {
  // 结果数据
  pub result: Vec<Cve>,
  // 分页每页
  pub limit: i64,
  // 分页偏移
  pub offset: i64,
  // 结果总数
  pub total: i64,
  #[serde(skip)]
  pub query: QueryCve,
}
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, Properties)]
pub struct QueryCve {
  // 精准CVE编号
  pub id: Option<String>,
  // 年份
  pub year: Option<i32>,
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
