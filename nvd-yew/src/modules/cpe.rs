use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use yew::prelude::*;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct Vendor {
  pub id: uuid::Uuid,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
  pub updated_at: NaiveDateTime,
  pub created_at: NaiveDateTime,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct VendorInfoList {
  // 结果数据
  pub result: Vec<Vendor>,
  // 分页每页
  pub size: i64,
  // 分页偏移
  pub page: i64,
  // 结果总数
  pub total: i64,
  #[serde(skip)]
  pub query: QueryVendor,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, Properties)]
pub struct QueryVendor {
  pub name: Option<String>,
  pub official: Option<bool>,
  // 分页每页
  pub size: Option<i64>,
  // 分页偏移
  pub page: Option<i64>,
}
