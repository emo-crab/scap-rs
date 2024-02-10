#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "db")]
use crate::schema::vendors;
use crate::uuid_serde;
use crate::{types::AnyValue, MetaData};
use chrono::NaiveDateTime;
#[cfg(feature = "db")]
use diesel::{Identifiable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi")]
use utoipa::ToSchema;
#[cfg(feature = "yew")]
use yew::Properties;

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "db", derive(Queryable, Identifiable, Selectable), diesel(table_name = vendors))]
#[cfg_attr(feature = "yew", derive(Properties))]
pub struct Vendor {
  #[serde(with = "uuid_serde")]
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub meta: AnyValue<MetaData>,
  pub updated_at: NaiveDateTime,
  pub created_at: NaiveDateTime,
}
