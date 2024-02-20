use chrono::NaiveDateTime;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

/// <https://nvd.nist.gov/developers/vulnerabilities>
/// This documentation assumes that you already understand at least one common programming language and are generally familiar with JSON RESTful services. JSON specifies the format of the data returned by the REST service. REST refers to a style of services that allow computers to communicate via HTTP over the Internet. Click here for a list of best practices and additional information on where to start. The NVD is also documenting popular workflows to assist developers working with the APIs.
///
/// Please note, new users are discouraged from starting with the 1.0 API as it will be retired in 2023 but you may still view documentation for the 1.0 Vulnerability and 1.0 Product APIs.
///
use crate::v2::{Keyword, LastModDate, LimitOffset};

/// The CVE API is used to easily retrieve information on a single CVE or a collection of CVE from the NVD. The NVD contains 232,639 CVE records. Because of this, its APIs enforce offset-based pagination to answer requests for large collections. Through a series of smaller “chunked” responses controlled by an offset startIndex and a page limit resultsPerPage users may page through all the CVE in the NVD.
///
/// The URL stem for retrieving CVE information is shown below.
///
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq, Builder)]
#[serde(rename_all = "camelCase")]
#[builder(setter(into), default)]
pub struct CveParameters {
  /// This parameter returns all CVE associated with a specific CPE. The exact value provided with cpeName is compared against the CPE Match Criteria within a CVE applicability statement. If the value of cpeName is considered to match, the CVE is included in the results.
  pub cpe_name: Option<String>,
  /// This parameter returns a specific vulnerability identified by its unique Common Vulnerabilities and Exposures identifier (the CVE ID). cveId will not accept {CVE-ID} for vulnerabilities not yet published in the NVD.
  pub cve_id: Option<String>,
  /// This parameter returns only the CVEs that match the provided {CVSSv2 vector string}. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV3Metrics.
  pub cvss_v2_metrics: Option<String>,
  /// This parameter returns only the CVEs that match the provided CVSSv2 qualitative severity rating. This parameter cannot be used in requests that include cvssV3Severity.
  pub cvss_v2_severity: Option<nvd_cvss::severity::SeverityTypeV2>,
  /// This parameter returns only the CVEs that match the provided {CVSSv3 vector string}. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV2Metrics.
  pub cvss_v3_metrics: Option<String>,
  /// This parameter returns only the CVEs that match the provided CVSSv3 qualitative severity rating. This parameter cannot be used in requests that include cvssV2Severity.
  /// Note: The NVD will not contain CVSS v3 vector strings with a severity of NONE. This is why that severity is not an included option.
  pub cvss_v3_severity: Option<nvd_cvss::severity::SeverityType>,
  /// This parameter returns only the CVE that include a weakness identified by Common Weakness Enumeration using the provided {CWE-ID}.
  /// Note: The NVD also makes use of two placeholder CWE-ID values NVD-CWE-Other and NVD-CWE-noinfo which can also be used.
  pub cwe_id: Option<String>,
  /// This parameter returns the CVE that contain a Technical Alert from US-CERT. Please note, this parameter is provided without a parameter value.
  pub has_cert_alerts: Option<bool>,
  /// This parameter returns the CVE that contain a Vulnerability Note from CERT/CC. Please note, this parameter is provided without a parameter value.
  pub has_cert_notes: Option<bool>,
  /// This parameter returns the CVE that appear in CISA's Known Exploited Vulnerabilities (KEV) Catalog. Please note, this parameter is provided without a parameter value.
  pub has_kev: Option<bool>,
  /// This parameter returns the CVE that contain information from MITRE's Open Vulnerability and Assessment Language (OVAL) before this transitioned to the Center for Internet Security (CIS). Please note, this parameter is provided without a parameter value.
  pub has_oval: Option<bool>,
  /// This parameter returns only CVE associated with a specific CPE, where the CPE is also considered vulnerable. The exact value provided with cpeName is compared against the CPE Match Criteria within a CVE applicability statement. If the value of cpeName is considered to match, and is also considered vulnerable the CVE is included in the results.
  pub is_vulnerable: Option<bool>,
  /// keyword [Keyword]
  #[serde(flatten)]
  pub keyword: Option<Keyword>,
  /// last_mod [LastModDate]
  #[serde(flatten)]
  pub last_mod: Option<LastModDate>,
  /// By default, the CVE API includes CVE records with the REJECT or Rejected status. This parameter excludes CVE records with the REJECT or Rejected status from API response. Please note, this parameter is provided without a parameter value.
  pub no_rejected: Option<bool>,
  /// pub_date [PubDate]
  #[serde(flatten)]
  pub pub_date: Option<PubDate>,
  /// limit_offset [LimitOffset]
  #[serde(flatten)]
  pub limit_offset: Option<LimitOffset>,
  /// This parameter returns CVE where the exact value of {sourceIdentifier} appears as a data source in the CVE record. The CVE API returns {sourceIdentifier} values within the descriptions object. The Source API returns detailed information on the organizations that provide the data contained in the NVD dataset, including every valid {sourceIdentifier} value.
  pub source_identifier: Option<String>,
  /// virtual_match [VirtualMatch]
  #[serde(flatten)]
  pub virtual_match: Option<VirtualMatch>,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VirtualMatch {
  /// This parameter filters CVE more broadly than cpeName. The exact value of {cpe match string} is compared against the CPE Match Criteria present on CVE applicability statements.
  pub virtual_match_string: String,
  #[serde(flatten)]
  pub version_start: Option<VersionStart>,
  #[serde(flatten)]
  pub version_end: Option<VersionEnd>,
}

/// The virtualMatchString parameter may be combined with versionStart and versionStartType to return only the CVEs associated with CPEs in specific version ranges.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VersionStart {
  pub version_start: String,
  pub version_start_type: String,
}

/// The virtualMatchString parameter may be combined with versionEnd and versionEndType to return only the CVEs associated with CPEs in specific version ranges.
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

/// If filtering by the published date, both pubStartDate and pubEndDate are required. The maximum allowable range when using any date range parameters is 120 consecutive days.
/// Values must be entered in the extended ISO-8601 date/time format:
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PubDate {
  pub pub_start_date: String,
  pub pub_end_date: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Vulnerabilities {
  pub cve: nvd_cves::api::CVE,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq, Builder, Default)]
#[serde(rename_all = "camelCase")]
#[builder(setter(into), default)]
pub struct CveHistoryParameters {
  pub cve_id: Option<String>,
  #[serde(flatten)]
  pub change_date: Option<ChangeDate>,
  pub event_name: Option<EventName>,
  #[serde(flatten)]
  pub limit_offset: Option<LimitOffset>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangeDate {
  pub change_start_date: String,
  pub change_end_date: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
pub enum EventName {
  #[serde(rename = "CVE Received")]
  CVEReceived,
  #[serde(rename = "Initial Analysis")]
  InitialAnalysis,
  Reanalysis,
  #[serde(rename = "CVE Modified")]
  CVEModified,
  #[serde(rename = "Modified Analysis")]
  ModifiedAnalysis,
  #[serde(rename = "CVE Translated")]
  CVETranslated,
  #[serde(rename = "Vendor Comment")]
  VendorComment,
  #[serde(rename = "CVE Source Update")]
  CVESourceUpdate,
  #[serde(rename = "CPE Deprecation Remap")]
  CPEDeprecationRemap,
  #[serde(rename = "CWE Remap")]
  CWERemap,
  #[serde(rename = "CVE Rejected")]
  CVERejected,
  #[serde(rename = "CVE Unrejected")]
  CVEUnRejected,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CveChanges {
  pub change: Change,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Change {
  pub cve_id: String,
  pub event_name: EventName,
  pub cve_change_id: String,
  pub source_identifier: String,
  pub created: NaiveDateTime,
  pub details: Vec<Details>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Details {
  pub action: Action,
  pub r#type: String,
  pub old_value: Option<String>,
  pub new_value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq)]
pub enum Action {
  Added,
  Removed,
  Changed,
}
