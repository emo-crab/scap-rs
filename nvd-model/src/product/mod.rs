#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "db")]
use crate::schema::products;
use crate::uuid_serde;
use crate::vendor::Vendor;
#[cfg(feature = "yew")]
use crate::MetaType;
use chrono::NaiveDateTime;
#[cfg(feature = "db")]
use diesel::{Associations, Identifiable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
#[cfg(feature = "db")]
use serde_json::Value;
#[cfg(feature = "openapi")]
use utoipa::{IntoParams, ToSchema};
#[cfg(feature = "yew")]
use yew::Properties;
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "db",
derive(Queryable,Identifiable,Associations,Selectable),
diesel(table_name = products,belongs_to(Vendor)))]
#[cfg_attr(feature = "yew", derive(Properties))]
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Product {
  #[serde(with = "uuid_serde")]
  pub id: Vec<u8>,
  #[serde(with = "uuid_serde")]
  pub vendor_id: Vec<u8>,
  pub official: u8,
  pub part: String,
  pub name: String,
  pub description: Option<String>,
  #[cfg(all(feature = "db", not(feature = "yew")))]
  pub meta: Value,
  #[cfg(all(feature = "yew", not(feature = "db")))]
  pub meta: MetaType,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
#[cfg_attr(feature = "yew", derive(Properties))]
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProductWithVendor {
  pub product: Product,
  pub vendor: Vendor,
}
#[cfg_attr(feature = "openapi", derive(IntoParams))]
// 产品查询参数
#[cfg_attr(feature = "yew", derive(Properties))]
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryProduct {
  pub vendor_id: Option<String>,
  pub vendor_name: Option<String>,
  pub name: Option<String>,
  pub part: Option<String>,
  pub official: Option<u8>,
  pub size: Option<i64>,
  pub page: Option<i64>,
}
