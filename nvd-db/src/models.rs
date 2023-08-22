use diesel::prelude::*;

use chrono::NaiveDateTime;
use diesel::sql_types::Json;

#[derive(Queryable, Debug, Clone)]
pub struct Cve {
  pub id: String,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
  pub references: Json,
  pub description: Json,
  pub cwe: Json,
  pub cvss3_id: Option<Vec<u8>>,
  pub cvss2_id: Option<Vec<u8>>,
  pub raw: Json,
  pub assigner: String,
  pub product_id: Vec<u8>,
  pub configurations: Json,
}

#[derive(Queryable, Debug, Clone)]
pub struct Cvss2 {
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
  pub ac_insuf_info: Option<String>,
  pub obtain_all_privilege: i8,
  pub obtain_user_privilege: i8,
  pub obtain_other_privilege: i8,
  pub user_interaction_required: Option<i8>,
}

#[derive(Queryable, Debug, Clone)]
pub struct Cvss3 {
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

#[derive(Queryable, Debug, Clone)]
pub struct Product {
  pub id: Vec<u8>,
  pub vendor_id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
  pub homepage: Option<String>,
  pub official: u8,
  pub part: String,
}

#[derive(Queryable, Debug, Clone)]
pub struct Vendor {
  pub id: Vec<u8>,
  pub name: String,
  pub description: Option<String>,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
  pub homepage: Option<String>,
  pub official: u8,
}
