use crate::v2::{Keyword, LastModDate, LimitOffset};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CpeParameters {
  pub cpe_name_id: Option<String>,
  pub cpe_match_string: Option<String>,
  #[serde(flatten)]
  pub keyword: Option<Keyword>,
  #[serde(flatten)]
  pub last_mod: Option<LastModDate>,
  // UUID
  pub match_criteria_id: Option<String>,
  #[serde(flatten)]
  pub limit_offset: Option<LimitOffset>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatchParameters {
  pub cve_id: Option<String>,
  #[serde(flatten)]
  pub last_mod: Option<LastModDate>,
  pub match_criteria_id: Option<String>,
  #[serde(flatten)]
  pub keyword: Option<Keyword>,
  #[serde(flatten)]
  pub limit_offset: Option<LimitOffset>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Products {
  pub cpe: Cpe,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Cpe {
  pub deprecated: bool,
  pub cpe_name: String,
  pub cpe_name_id: String,
  pub created: NaiveDateTime,
  pub last_modified: NaiveDateTime,
  #[serde(default)]
  pub titles: Vec<Titles>,
  #[serde(default)]
  pub refs: Vec<Refs>,
  #[serde(default)]
  pub deprecated_by: Vec<DeprecatedBy>,
  #[serde(default)]
  pub deprecates: Vec<Deprecates>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Titles {
  pub title: String,
  pub lang: String,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Refs {
  pub r#ref: String,
  pub r#type: RefType,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
pub enum RefType {
  Advisory,
  #[serde(rename = "Change Log")]
  ChangeLog,
  Product,
  Project,
  Vendor,
  Version,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeprecatedBy {
  pub cpe_name: String,
  pub cpe_name_id: String,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Deprecates {
  pub cpe_name: String,
  pub cpe_name_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatchStrings {
  pub match_string: MatchString,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatchString {
  pub criteria: String,
  pub match_criteria_id: String,
  pub version_start_excluding: Option<String>,
  pub version_start_including: Option<String>,
  pub version_end_excluding: Option<String>,
  pub version_end_including: Option<String>,
  pub created: NaiveDateTime,
  pub last_modified: NaiveDateTime,
  pub cpe_last_modified: Option<NaiveDateTime>,
  pub status: Status,
  #[serde(default)]
  pub matches: Vec<Matches>,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
pub enum Status {
  Active,
  Inactive,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Matches {
  pub cpe_name: String,
  pub cpe_name_id: String,
}
