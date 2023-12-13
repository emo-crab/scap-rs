pub mod cve_db;
pub mod cve_product_db;
pub mod cwe_db;
pub mod product_db;
pub mod vendor_db;

use crate::schema::*;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(belongs_to(Cve))]
#[diesel(belongs_to(Product))]
#[diesel(table_name = cve_product)]
#[diesel(primary_key(cve_id, product_id))]
pub struct CveProduct {
  pub cve_id: String,
  pub product_id: Vec<u8>,
}

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
  pub timeline: Value,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

#[derive(
  Queryable, Selectable, Identifiable, Associations, Debug, PartialEq, Serialize, Deserialize,
)]
#[diesel(belongs_to(Vendor))]
pub struct Product {
  #[serde(skip)]
  pub id: Vec<u8>,
  #[serde(skip)]
  pub vendor_id: Vec<u8>,
  pub official: u8,
  pub part: String,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

#[derive(Queryable, Identifiable, Selectable, Debug, PartialEq, Serialize, Deserialize)]
pub struct Vendor {
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
  pub updated_at: NaiveDateTime,
  pub created_at: NaiveDateTime,
}

#[derive(Queryable, Identifiable, Selectable, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cwe {
  pub id: i32,
  pub name: String,
  pub description: String,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
