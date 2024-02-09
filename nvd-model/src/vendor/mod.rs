#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "db")]
use crate::schema::vendors;
use crate::uuid_serde;
#[cfg(feature = "yew")]
use crate::MetaType;
use chrono::NaiveDateTime;
#[cfg(feature = "db")]
use diesel::{Identifiable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
#[cfg(feature = "db")]
use serde_json::Value;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;
#[cfg(feature = "yew")]
use yew::Properties;

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "db", derive(Queryable, Identifiable, Selectable),diesel(table_name = vendors))]
#[cfg_attr(feature = "yew", derive(Properties))]
pub struct Vendor {
  #[serde(with = "uuid_serde")]
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  #[cfg(all(feature = "db", not(feature = "yew")))]
  pub meta: Value,
  #[cfg(all(feature = "yew", not(feature = "db")))]
  pub meta: MetaType,
  pub updated_at: NaiveDateTime,
  pub created_at: NaiveDateTime,
}
