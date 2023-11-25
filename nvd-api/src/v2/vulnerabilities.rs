use crate::v2::{Keyword, LastModDate, LimitOffset};
use serde::{Deserialize, Serialize};

// https://nvd.nist.gov/developers/vulnerabilities
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CveParameters {
  pub cpe_name: Option<String>,
  pub cve_id: Option<String>,
  pub cvss_v2_metrics: Option<String>,
  pub cvss_v2_severity: Option<cvss::severity::SeverityTypeV2>,
  pub cvss_v3_metrics: Option<String>,
  pub cvss_v3_severity: Option<cvss::severity::SeverityType>,
  pub cwe_id: Option<String>,
  pub has_cert_alerts: Option<bool>,
  pub has_cert_notes: Option<bool>,
  pub has_kev: Option<bool>,
  pub has_oval: Option<bool>,
  pub is_vulnerable: Option<bool>,
  #[serde(flatten)]
  pub keyword: Option<Keyword>,
  #[serde(flatten)]
  pub last_mod: Option<LastModDate>,
  pub no_rejected: Option<bool>,
  #[serde(flatten)]
  pub pub_date: Option<PubDate>,
  #[serde(flatten)]
  pub limit_offset: Option<LimitOffset>,
  pub source_identifier: Option<String>,
  #[serde(flatten)]
  pub virtual_match: Option<VirtualMatch>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VirtualMatch {
  pub virtual_match_string: String,
  #[serde(flatten)]
  pub version_start: Option<VersionStart>,
  #[serde(flatten)]
  pub version_end: Option<VersionEnd>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VersionStart {
  pub version_start: String,
  pub version_start_type: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VersionEnd {
  pub version_end: String,
  pub version_end_type: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VersionType {
  Including,
  Excluding,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PubDate {
  pub pub_start_date: String,
  pub pub_end_date: String,
}


