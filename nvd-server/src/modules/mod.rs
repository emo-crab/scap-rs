use chrono::NaiveDateTime;
use diesel::prelude::*;
use pagination::ListResponse;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

use crate::schema::*;

pub mod cve_db;
pub mod cve_exploit_db;
pub mod cve_product_db;
pub mod cwe_db;
pub mod exploit_db;
mod pagination;
pub mod product_db;
pub mod vendor_db;

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(belongs_to(Cve))]
#[diesel(belongs_to(Product))]
#[diesel(table_name = cve_product)]
#[diesel(primary_key(cve_id, product_id))]
pub struct CveProduct {
  pub cve_id: String,
  pub product_id: Vec<u8>,
}
#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(belongs_to(Cve))]
#[diesel(belongs_to(Exploit))]
#[diesel(table_name = cve_exploit)]
#[diesel(primary_key(cve_id, exploit_id))]
pub struct CveExploit {
  pub cve_id: String,
  pub exploit_id: Vec<u8>,
}
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Queryable, Serialize, Deserialize, Identifiable, Debug, PartialEq)]
#[diesel(table_name = cves)]
pub struct Cve {
  pub id: String,
  pub year: i32,
  pub assigner: String,
  pub description: Value,
  pub severity: String,
  pub metrics: Value,
  pub weaknesses: Value,
  pub configurations: Value,
  pub references: Value,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(
  Queryable, Selectable, Identifiable, Associations, Debug, PartialEq, Serialize, Deserialize,
)]
#[diesel(belongs_to(Vendor))]
pub struct Product {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub official: u8,
  pub part: String,
  pub name: String,
  pub description: Option<String>,
  pub meta: Value,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Queryable, Identifiable, Selectable, Debug, PartialEq, Serialize, Deserialize)]
pub struct Vendor {
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub meta: Value,
  pub updated_at: NaiveDateTime,
  pub created_at: NaiveDateTime,
}
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Queryable, Identifiable, Selectable, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cwe {
  pub id: i32,
  pub name: String,
  pub description: String,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Queryable, Selectable, Identifiable, Debug, PartialEq, Serialize, Deserialize)]
#[diesel(table_name = exploits)]
pub struct Exploit {
  pub id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
  pub source: String,
  pub path: String,
  pub meta: Value,
  pub verified: u8,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
