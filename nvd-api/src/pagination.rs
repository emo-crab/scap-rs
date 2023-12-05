use crate::error::ErrorResponse;
use crate::v2::products::{MatchStrings, Products};
use crate::v2::vulnerabilities::{CveChanges, Vulnerabilities};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
  #[serde(flatten)]
  pub results: Object,
  pub results_per_page: u32,
  pub start_index: u32,
  pub total_results: u32,
  pub format: String,
  pub version: String,
  pub timestamp: NaiveDateTime,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Object {
  Vulnerabilities(Vec<Vulnerabilities>),
  CveChanges(Vec<CveChanges>),
  Products(Vec<Products>),
  MatchStrings(Vec<MatchStrings>),
  Error {
    #[serde(flatten)]
    error: ErrorResponse,
  },
}
