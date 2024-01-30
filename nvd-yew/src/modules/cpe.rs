use std::collections::HashMap;

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use yew::prelude::*;

pub type MetaType = HashMap<String, HashMap<String, String>>;

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct Vendor {
  #[serde(with = "uuid_serde")]
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub meta: MetaType,
  pub updated_at: NaiveDateTime,
  pub created_at: NaiveDateTime,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct Product {
  #[serde(with = "uuid_serde")]
  pub id: Vec<u8>,
  #[serde(with = "uuid_serde")]
  pub vendor_id: Vec<u8>,
  pub official: u8,
  pub part: String,
  pub name: String,
  pub description: Option<String>,
  pub meta: MetaType,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq, Properties)]
pub struct ProductWithVendor {
  pub product: Product,
  pub vendor: Vendor,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, Properties)]
pub struct QueryCpe {
  pub vendor_id: Option<String>,
  pub name: Option<String>,
  pub part: Option<String>,
  #[serde(skip)]
  pub vendor_name: Option<String>,
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
