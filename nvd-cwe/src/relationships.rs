use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename(deserialize = "Relationships"))]
pub struct Relationships {
  #[serde(rename(deserialize = "Has_Member"), default)]
  pub has_members: Vec<HasMember>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename(deserialize = "Has_Member"))]
pub struct HasMember {
  #[serde(rename(deserialize = "@CWE_ID"))]
  pub cwe_id: i64,
  #[serde(rename(deserialize = "@View_ID"))]
  pub view_id: i64,
}
