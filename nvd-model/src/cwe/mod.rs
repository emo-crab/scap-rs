use chrono::NaiveDateTime;
#[cfg(feature = "db")]
use diesel::{Identifiable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi")]
use utoipa::{IntoParams, ToSchema};
#[cfg(feature = "yew")]
use yew::Properties;

#[cfg(feature = "db")]
use crate::schema::cwes;

#[cfg(feature = "db")]
pub mod db;

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "db", derive(Queryable, Identifiable, Selectable), diesel(table_name = cwes))]
#[cfg_attr(feature = "yew", derive(Properties))]
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Cwe {
  pub id: i32,
  pub name: String,
  pub description: String,
  pub name_zh: String,
  pub description_zh: String,
  pub status: String,
  pub remediation: String,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

#[cfg_attr(feature = "openapi", derive(IntoParams))]
#[cfg_attr(feature = "yew", derive(Properties))]
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryCwe {
  pub id: Option<i32>,
  pub name: Option<String>,
  pub size: Option<i64>,
  pub page: Option<i64>,
}
