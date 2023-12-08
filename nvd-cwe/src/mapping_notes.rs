use crate::structured_text::StructuredText;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(deserialize = "PascalCase"))]
pub struct MappingNotes {
  pub usage: Usage,
  pub rationale: StructuredText,
  pub comments: StructuredText,
  pub reasons: Reasons,
  pub suggestions: Option<Suggestions>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestions {
  #[serde(rename(deserialize = "Suggestion"))]
  pub suggestion: Vec<Suggestion>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestion {
  #[serde(rename(deserialize = "@CWE_ID"))]
  pub cwe_id: i32,
  #[serde(rename(deserialize = "@Comment"))]
  pub comment: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(deserialize = "PascalCase"))]
pub struct Reasons {
  #[serde(default)]
  pub reason: Vec<Reason>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
  #[serde(rename(deserialize = "@Type"))]
  pub r#type: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct Usage {
  #[serde(rename(deserialize = "$text"))]
  pub usage: UsageEnum,
}

/// The UsageEnumeration simple type is used for whether this CWE entry is supported for mapping.
#[derive(Debug, Deserialize, Serialize)]
pub enum UsageEnum {
  Discouraged,
  Prohibited,
  Allowed,
  #[serde(rename(deserialize = "Allowed-with-Review"))]
  AllowedWithReview,
}
