use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use yew::prelude::*;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct Cve {
  pub id: String,
  pub year: i32,
  pub official: u8,
  pub assigner: String,
  pub references: cve::References,
  pub description: cve::Description,
  // pub problem_type: cve::ProblemType,
  pub cvss3_vector: String,
  pub cvss3_score: f32,
  pub cvss2_vector: String,
  pub cvss2_score: f32,
  // pub configurations: cve::configurations::Configurations,
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
}
