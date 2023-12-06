use serde::{Deserialize, Serialize};

pub mod api;
pub mod products;
pub mod vulnerabilities;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LimitOffset {
  pub results_per_page: Option<u64>,
  pub start_index: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Keyword {
  pub keyword_exact_match: bool,
  pub keyword_search: String,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LastModDate {
  /// rfc3339 string
  pub last_mod_start_date: String,
  /// rfc3339 string
  pub last_mod_end_date: String,
}
