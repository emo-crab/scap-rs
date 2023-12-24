use serde::{Deserialize, Serialize};
#[derive(Default, Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct Paging {
  // 分页每页
  pub size: i64,
  // 分页偏移
  pub page: i64,
  // 结果总数
  pub total: i64,
}
#[derive(Default, Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct ListResponse<T, Q> {
  pub result: Vec<T>,
  #[serde(flatten)]
  pub paging: Paging,
  #[serde(skip)]
  pub query: Q,
}
