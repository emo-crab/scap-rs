//! Paging management for unified API response
use crate::error::ErrorResponse;
use crate::v2::products::{MatchStrings, Products};
use crate::v2::vulnerabilities::{CveChanges, Vulnerabilities};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

/// The API returns seven primary objects in the body of the response: resultsPerPage, startIndex, totalResults, format, version, timestamp, and [Object].
/// The format and version objects identify the format and version of the API response. timestamp identifies when the response was generated.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
  /// results [Object]
  #[serde(flatten)]
  pub results: Object,
  /// pagination [Pagination]
  #[serde(flatten)]
  pub pagination: Pagination,
  /// format
  pub format: String,
  /// version
  pub version: String,
  /// timestamp
  pub timestamp: NaiveDateTime,
}
/// If the value of totalResults is greater than the value of resultsPerPage, then additional requests are necessary to return the remaining [Object].
/// The parameter startIndex may be used in subsequent requests to identify the starting point for the next request. More information and the best practices for using resultsPerPage and startIndex are described above.
///
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
  /// resultsPerPage
  pub results_per_page: u32,
  /// startIndex
  pub start_index: u32,
  /// totalResults
  pub total_results: u32,
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
