pub mod configurations;

use crate::date_format;
use crate::impact::ImpactMetrics;
use crate::v4::configurations::Configurations;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
// https://nvd.nist.gov/general/News/JSON-1-1-Vulnerability-Feed-Release
// https://github.com/CVEProject/cve-schema
// https://raw.gitmirror.com/CVEProject/cve-schema/master/schema/v4.0/DRAFT-JSON-file-format-v4.md
// https://www.cve.org/Downloads
// https://github.com/CVEProject/cvelist

/// These objects can in turn contain more objects, arrays, strings and so on. The reason for this is so that each top level object type can contain self-identifying data such as CVE_Data_version. Most objects can in turn contains virtually any other object. In general, if you traverse into the nested tree of objects you should not encounter any chains that contains more than one instance of a given object container. Simply put you should not for example encounter a chain such as: root, CVE_affects, CVE_configuration, CVE_workaround, CVE_configuration. Please note that this rule may be subject to change as we get new container types and use cases.
#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
#[serde(deny_unknown_fields)]
pub struct CVEContainer {
  /// This string identifies what kind of data is held in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what kind of file this is. Valid values for this string are CVE, CNA, CVEMENTOR.
  pub CVE_data_type: String,
  /// This string identifies what data format is used in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what format of data is used. Valid values for this string are MITRE, it can also be user defined (e.g. for internal use).
  pub CVE_data_format: String,
  /// This identifies which version of the data format is in use. This is mandatory and designed to prevent problems with attempting to detect what format of data is used.
  pub CVE_data_version: String,
  /// numberOfCVEs
  pub CVE_data_numberOfCVEs: String,
  /// last update time for this entry
  pub CVE_data_timestamp: String,
  /// There are several special string values that can exist at the root level of the CVE ID JSON data, and one special one, the CVE_data_version, which can exist in the root or within any container.
  pub CVE_Items: Vec<CVEItem>,
}

// 单个CVE信息
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase"), deny_unknown_fields)]
#[allow(clippy::upper_case_acronyms)]
pub struct CVEItem {
  // CVE 信息
  pub cve: CVE,
  // 影响
  pub impact: ImpactMetrics,
  // 配置
  pub configurations: Configurations,
  // 公开时间
  #[serde(with = "date_format")]
  pub published_date: NaiveDateTime,
  // 最后修改时间
  #[serde(with = "date_format")]
  pub last_modified_date: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CVE {
  /// This string identifies what kind of data is held in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what kind of file this is. Valid values for this string are CVE, CNA, CVEMENTOR.
  pub data_type: String,
  /// This string identifies what data format is used in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what format of data is used. Valid values for this string are MITRE, it can also be user defined (e.g. for internal use).
  pub data_format: String,
  /// This identifies which version of the data format is in use. This is mandatory and designed to prevent problems with attempting to detect what format of data is used.
  pub data_version: String,
  /// CVE_data_meta
  #[serde(rename(deserialize = "CVE_data_meta"))]
  pub meta: Meta,
  // 参考
  pub references: References,
  // 描述
  pub description: Descriptions,
  // 问题类型 关联：CWE
  #[serde(rename(deserialize = "problemtype"))]
  pub problem_type: ProblemType,
}

/// These URLs are supplemental information relevant to the vulnerability, which include details that may not be present in the CVE Description. References are given resource tags such as third-party advisory, vendor advisory, technical paper, press/media, VDB entries, etc. These tags can help users quickly categorize the type of information each reference contains. References for a CVE are provided through the CVE list, the NVD does not have direct control over them. If you have concerns with existing CVE references or find other publicly available information that would be useful, then you can submit a request using the form at <https://cveform.mitre.org/> for the CVE Assignment Team to review.
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct References {
  pub reference_data: Vec<Reference>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Reference {
  pub url: String,
  #[serde(default)]
  pub name: String,
  #[serde(alias = "refsource")]
  pub source: String,
  #[serde(default)]
  pub tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Descriptions {
  pub description_data: Vec<Description>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Description {
  pub lang: String,
  pub value: String,
}

/// This is metadata about the CVE ID such as the CVE ID, who requested it, who assigned it, when it was requested, when it was assigned, the current state (PUBLIC, REJECT, etc.) and so on.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Meta {
  /// CVE-YEAR-NNNNNNN - the CVE ID in the format listed in <http://cve.mitre.org/cve/identifiers/syntaxchange.html#new>
  #[serde(rename(deserialize = "ID"))]
  pub id: String,
  /// Assigner ID - the assigner of the CVE (email address)
  #[serde(rename(deserialize = "ASSIGNER"))]
  pub assigner: String,
}

/// This is problem type information (e.g. CWE identifier).
///
/// Must contain: At least one entry, can be text, OWASP, CWE, please note that while only one is required you can use more than one (or indeed all three) as long as they are correct.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProblemType {
  #[serde(rename = "problemtype_data")]
  pub problem_type_data: Vec<Weaknesses>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Weaknesses {
  pub source: Option<String>,
  pub r#type: Option<String>,
  pub description: Vec<Description>,
}
