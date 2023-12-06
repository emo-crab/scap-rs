use serde::{Deserialize, Serialize};
use yew::prelude::*;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct Cwe {
  pub id: i32,
  pub name: String,
  pub description: String,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct CweInfoList {
  // 结果数据
  pub result: Vec<Cwe>,
  // 分页每页
  pub limit: i64,
  // 分页偏移
  pub offset: i64,
  // 结果总数
  pub total: i64,
  #[serde(skip)]
  pub query: QueryCwe,
}
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, Properties)]
pub struct QueryCwe {
  // 精准CWE编号
  pub id: Option<i32>,
  // 分页每页
  pub limit: Option<i64>,
  // 分页偏移
  pub offset: Option<i64>,
}
