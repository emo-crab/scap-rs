use serde::{Deserialize, Serialize};

mod api;
mod vulnerabilities;
mod cve_history;
mod products;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LimitOffset {
    results_per_page: Option<u64>,
    start_index: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Vulnerabilities {
    cve: cve::api::CVE,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Keyword {
    keyword_exact_match: bool,
    keyword_search: String,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LastModDate {
    last_mod_start_date: String,
    last_mod_end_date: String,
}