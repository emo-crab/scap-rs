use chrono::NaiveDateTime;
use crate::error::ErrorResponse;
use serde::{Deserialize, Serialize};
use crate::v2::Vulnerabilities;

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

/// <https://developers.notion.com/reference/pagination#responses>
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct ListResponse<T> {
    pub results: Vec<T>,
    pub results_per_page: u32,
    pub start_index: u32,
    pub total_results: u32,
    pub format: String,
    pub version: String,
    pub timestamp: NaiveDateTime,
}

impl<T> ListResponse<T> {
    pub fn results(&self) -> &[T] {
        &self.results
    }
}

impl ListResponse<Object> {}

#[derive(Eq, Serialize, Deserialize, Clone, Debug, PartialEq)]
// #[serde(tag = "format")]
#[serde(rename_all = "snake_case")]
pub enum Object {
    Vulnerabilities {
        #[serde(flatten)]
        cve: Vulnerabilities,
    },
    Error {
        #[serde(flatten)]
        error: ErrorResponse,
    },
}