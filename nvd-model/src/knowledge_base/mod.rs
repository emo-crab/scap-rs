use chrono::NaiveDateTime;
#[cfg(feature = "db")]
use diesel::{Identifiable, Queryable, QueryableByName, Selectable};
use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi")]
use utoipa::{IntoParams, ToSchema};

#[cfg(feature = "db")]
use crate::schema::knowledge_base;
use crate::types::AnyValue;
use crate::types::MetaData;

#[cfg(feature = "db")]
pub mod db;

#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, PartialEq, Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "db", derive(Queryable, Selectable, Identifiable, QueryableByName), diesel(table_name = knowledge_base))]
pub struct KnowledgeBase {
  pub id: Vec<u8>,
  pub name: String,
  pub description: String,
  pub source: String,
  pub links: String,
  pub meta: AnyValue<MetaData>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

#[cfg_attr(feature = "openapi", derive(IntoParams))]
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct QueryKnowledgeBase {
  pub id: Option<Vec<u8>>,
  pub cve: Option<String>,
  pub name: Option<String>,
  pub description: Option<String>,
  pub source: Option<String>,
  pub links: Option<String>,
  pub size: Option<i64>,
  pub page: Option<i64>,
}
