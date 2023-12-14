use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use yew::prelude::*;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct Vendor {
  #[serde(with = "uuid_serde")]
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
  pub updated_at: NaiveDateTime,
  pub created_at: NaiveDateTime,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct Product {
  #[serde(with = "uuid_serde")]
  pub id: Vec<u8>,
  #[serde(with = "uuid_serde")]
  pub vendor_id: Vec<u8>,
  pub official: u8,
  pub part: String,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct ProductInfoList {
  // 结果数据
  pub result: Vec<Product>,
  // 分页每页
  pub size: i64,
  // 分页偏移
  pub page: i64,
  // 结果总数
  pub total: i64,
  #[serde(skip)]
  pub query: QueryProduct,
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
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, Properties)]
pub struct QueryProduct {
  pub name: Option<String>,
  pub official: Option<bool>,
  // 分页每页
  pub size: Option<i64>,
  // 分页偏移
  pub page: Option<i64>,
}
mod uuid_serde {
  use serde::{Deserializer, Serializer};

  pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    match uuid::Uuid::from_slice(v) {
      Ok(u) => uuid::serde::compact::serialize(&u, s),
      Err(e) => Err(serde::ser::Error::custom(e)),
    }
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    match uuid::serde::compact::deserialize(d) {
      Ok(u) => Ok(u.as_bytes().to_vec()),
      Err(e) => Err(serde::de::Error::custom(e)),
    }
  }
}
