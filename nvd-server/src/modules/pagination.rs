use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, ToSchema)]
pub struct Paging {
  // 分页每页
  pub size: i64,
  // 分页偏移
  pub page: i64,
  // 结果总数
  pub total: i64,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, IntoParams, ToSchema, Default)]
pub struct QueryPaging {
  // 分页每页
  pub size: Option<i64>,
  // 分页偏移
  pub page: Option<i64>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone, ToSchema)]
pub struct ListResponse<T> {
  pub result: Vec<T>,
  #[serde(flatten)]
  pub paging: Paging,
}

impl<T> ListResponse<T> {
  pub fn new(result: Vec<T>, total: i64, page: i64, size: i64) -> Self {
    Self {
      result,
      paging: Paging { size, page, total },
    }
  }
  pub fn results(&self) -> &[T] {
    &self.result
  }
}
