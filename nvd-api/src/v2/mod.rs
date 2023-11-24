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
