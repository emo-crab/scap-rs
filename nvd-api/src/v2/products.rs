use crate::v2::{Keyword, LastModDate, LimitOffset};
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
