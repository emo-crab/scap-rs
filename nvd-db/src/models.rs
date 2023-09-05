use crate::schema::*;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde_json::Value;
use serde::{Deserialize, Serialize};
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
#[diesel(belongs_to(Cvss2))]
#[diesel(belongs_to(Cvss3))]
#[diesel(table_name = cves)]
pub struct Cve {
  pub id: String,
  pub year: i32,
  pub official: u8,
  pub assigner: String,
  pub references: Value,
  pub description: Value,
  pub problem_type: Value,
  pub cvss3_id: Option<Vec<u8>>,
  pub cvss2_id: Option<Vec<u8>>,
  pub configurations: Value,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

#[derive(Queryable, Debug, Clone, Serialize, Deserialize)]
#[diesel(table_name = cvss2)]
pub struct Cvss2 {
  #[serde(skip)]
  pub id: Vec<u8>,
  pub version: String,
  pub vector_string: String,
  pub access_vector: String,
  pub access_complexity: String,
  pub authentication: String,
  pub confidentiality_impact: String,
  pub integrity_impact: String,
  pub availability_impact: String,
  pub base_score: f32,
  pub exploitability_score: f32,
  pub impact_score: f32,
  pub severity: String,
  pub ac_insuf_info: Option<u8>,
  pub obtain_all_privilege: u8,
  pub obtain_user_privilege: u8,
  pub obtain_other_privilege: u8,
  pub user_interaction_required: Option<u8>,
}

#[derive(Queryable, Debug, Clone, Serialize, Deserialize)]
#[diesel(table_name = cvss3)]
pub struct Cvss3 {
  #[serde(skip)]
  pub id: Vec<u8>,
  pub version: String,
  pub vector_string: String,
  pub attack_vector: String,
  pub attack_complexity: String,
  pub privileges_required: String,
  pub user_interaction: String,
  pub scope: String,
  pub confidentiality_impact: String,
  pub integrity_impact: String,
  pub availability_impact: String,
  pub base_score: f32,
  pub base_severity: String,
  pub exploitability_score: f32,
  pub impact_score: f32,
}

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(belongs_to(Vendor))]
pub struct Product {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub official: u8,
  pub part: String,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}

#[derive(Queryable, Identifiable, Selectable, Debug, PartialEq)]
pub struct Vendor {
  pub id: Vec<u8>,
  pub official: u8,
  pub name: String,
  pub description: Option<String>,
  pub homepage: Option<String>,
  pub updated_at: NaiveDateTime,
  pub created_at: NaiveDateTime,
}

#[derive(Queryable, Debug)]
pub struct Cwe {
  pub id: i32,
  pub name: String,
  pub description: String,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
}
