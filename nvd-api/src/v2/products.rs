use chrono::NaiveDateTime;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::v2::{Keyword, LastModDate, LimitOffset};

///  # Products
/// This documentation assumes that you already understand at least one common programming language and are generally familiar with JSON RESTful services. JSON specifies the format of the data returned by the REST service. REST refers to a style of services that allow computers to communicate via HTTP over the Internet. Click here for a list of best practices and additional information on where to start. The NVD is also documenting popular workflows to assist developers working with the APIs.
///
/// Please note, new users are discouraged from starting with the 1.0 API as it will be retired in 2023 but you may still view documentation for the 1.0 Vulnerability and 1.0 Product APIs.
///
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq, Builder)]
#[serde(rename_all = "camelCase")]
#[builder(setter(into), default)]
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

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq, Builder)]
#[serde(rename_all = "camelCase")]
#[builder(setter(into), default)]
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
  #[serde(default)]
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

impl Default for RefType {
  fn default() -> Self {
    Self::ChangeLog
  }
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

/// Match Criteria API
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MatchStrings {
  pub match_string: nvd_cves::v4::configurations::Match,
}
