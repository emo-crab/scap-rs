use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
struct CVE {
    cpe_name: Option<String>,
    cve_id: Option<String>,
    cvss_v2_metrics: Option<String>,
    cvss_v2_severity: Option<cvss::severity::SeverityTypeV2>,
    cvss_v3_metrics: Option<String>,
    cvss_v3_severity: Option<cvss::severity::SeverityType>,
    cwe_id: Option<String>,
    has_cert_alerts: Option<bool>,
    has_cert_notes: Option<bool>,
    has_kev: Option<bool>,
    has_oval: Option<bool>,
    is_vulnerable: Option<bool>,
    #[serde(flatten)]
    keyword: Option<Keyword>,
    #[serde(flatten)]
    last_mod: Option<LastModDate>,
    no_rejected: Option<bool>,
    #[serde(flatten)]
    pub_date: Option<PubDate>,
    #[serde(flatten)]
    limit_offset: Option<LimitOffset>,
    source_identifier: Option<String>,
    #[serde(flatten)]
    virtual_match: Option<VirtualMatch>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
struct VirtualMatch {
    virtual_match_string: String,
    #[serde(flatten)]
    version_start: Option<VersionStart>,
    #[serde(flatten)]
    version_end: Option<VersionEnd>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
struct VersionStart {
    version_start: String,
    version_start_type: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
struct VersionEnd {
    version_end: String,
    version_end_type: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
enum VersionType {
    Including,
    Excluding,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
struct LimitOffset {
    results_per_page: Option<u64>,
    start_index: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
struct PubDate {
    pub_start_date: String,
    pub_end_date: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
struct Keyword {
    keyword_exact_match: bool,
    keyword_search: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
struct LastModDate {
    last_mod_start_date: String,
    last_mod_end_date: String,
}