use crate::error::ErrorResponse;
use crate::v2::products::{MatchStrings, Products};
use crate::v2::vulnerabilities::{Change, Vulnerabilities};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
#[serde(transparent)]
pub struct PagingCursor(String);

#[derive(Serialize, Debug, Eq, PartialEq, Default, Clone)]
pub struct Paging {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub start_cursor: Option<PagingCursor>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub page_size: Option<u8>,
}

pub trait Pageable {
  fn start_from(self, starting_point: Option<PagingCursor>) -> Self;
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all(deserialize = "camelCase"))]
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
  CveChanges(Vec<Change>),
  Products(Vec<Products>),
  MatchStrings(Vec<MatchStrings>),
  Error {
    #[serde(flatten)]
    error: ErrorResponse,
  },
}
