//! nvd-api v2
use serde::{Deserialize, Serialize};

pub mod api;
pub mod products;
pub mod vulnerabilities;
/// pagination
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LimitOffset {
  pub results_per_page: Option<u64>,
  pub start_index: Option<u64>,
}
/// If the value of keywordSearch is a phrase, i.e., contains more than one term, including keywordExactMatch returns only the CVEs matching the phrase exactly. Otherwise, the results will contain records having any of the terms. If filtering by keywordExactMatch, keywordSearch is required. Please note, this parameter is provided without a parameter value.
/// Please note, empty spaces in the URL should be encoded in the request as "%20". The user agent may handle this encoding automatically. Multiple {keywords} function like an 'AND' statement. This returns results where all keywords exist somewhere in the current description, though not necessarily together. Keyword search operates as though a wildcard is placed after each keyword provided. For example, providing "circle" will return results such as "circles" but not "encircle".
///
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Keyword {
  /// By default, keywordSearch returns any CVE where a word or phrase is found in the current description.
  pub keyword_exact_match: bool,
  /// This parameter returns only the CVEs where a word or phrase is found in the current description. Descriptions associated with CVE are maintained by the CVE Assignment Team through coordination with CVE Numbering Authorities (CNAs). The NVD has no control over CVE descriptions.
  pub keyword_search: String,
}
/// Values must be entered in the extended ISO-8601 date/time format:
/// If filtering by the last modified date, both lastModStartDate and lastModEndDate are required. The maximum allowable range when using any date range parameters is 120 consecutive days.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LastModDate {
  /// lastModStartDate
  pub last_mod_start_date: String,
  /// lastModEndDate
  pub last_mod_end_date: String,
}
