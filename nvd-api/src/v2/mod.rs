use serde::{Deserialize, Serialize};

mod vulnerabilities;
mod api;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
pub struct Vulnerabilities {
    // cve: cve::CVE,
}