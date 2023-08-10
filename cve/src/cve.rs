use crate::node;
use cvss::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// 单个CVE信息
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::upper_case_acronyms)]
pub struct CVEItem {
  // CVE 信息
  pub cve: CVE,
  // 影响
  pub impact: Impact,
  // 配置
  pub configurations: Configurations,
  // 公开时间
  pub published_date: String,
  // 最后修改时间
  pub last_modified_date: String,
}
/// impact
/// This is impact type information (e.g. a text description, CVSSv2, CVSSv3, etc.).
///
/// Must contain: At least one entry, can be text, CVSSv2, CVSSv3, others may be added
///
/// Mandatory in: none, please note there is a good chance this container may become required as part of the standard, currently the DWF requires it.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Impact {
  // TODO: Implement V1?
  // cvssV2 过期
  #[serde(skip_serializing_if = "Option::is_none")]
  pub base_metric_v2: Option<ImpactMetricV2>,
  // cvssV3
  pub base_metric_v3: Option<ImpactMetricV3>,
  // TODO: Implement V4?
}
/// cvss v2
///
/// The CVSSv2 (https://www.first.org/cvss/v2/guide) scoring data, split up into Base Metrics Group (BM), Temporal Metrics Group (TM) and Environmental Metrics Group (EM).
///
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ImpactMetricV2 {
  pub cvss_v2: cvss::v2::CVSS,
  // 漏洞的可利用 评分
  pub exploitability_score: f32,
  // 评分
  pub impact_score: f32,
  // 评级
  pub severity: String,
  pub ac_insuf_info: Option<bool>,
  pub obtain_all_privilege: bool,
  pub obtain_user_privilege: bool,
  pub obtain_other_privilege: bool,
  // 用户交互
  pub user_interaction_required: Option<bool>,
}
/// cvss v3
///
/// The CVSSv3 (https://www.first.org/cvss/specification-document) scoring data.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ImpactMetricV3 {
  pub cvss_v3: cvss::v3::CVSS,
  // 漏洞的可利用 评分
  pub exploitability_score: f32,
  // cvss 评分
  pub impact_score: f32,
}

impl FromStr for ImpactMetricV3 {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    match cvss::v3::CVSS::from_str(s) {
      Ok(c) => {
        let exploitability_score = c.exploitability_score();
        let impact_score = c.impact_score();
        Ok(Self {
          cvss_v3: c,
          exploitability_score,
          impact_score,
        })
      }
      Err(err) => Err(err),
    }
  }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configurations {
  // 版本
  #[serde(rename = "CVE_data_version")]
  pub data_version: String,
  // 漏洞节点
  pub nodes: Vec<node::Node>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CVE {
  /// This string identifies what kind of data is held in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what kind of file this is. Valid values for this string are CVE, CNA, CVEMENTOR.
  pub data_type: String,
  /// This string identifies what data format is used in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what format of data is used. Valid values for this string are MITRE, it can also be user defined (e.g. for internal use).
  pub data_format: String,
  /// This identifies which version of the data format is in use. This is mandatory and designed to prevent problems with attempting to detect what format of data is used.
  pub data_version: String,
  /// CVE_data_meta
  #[serde(rename = "CVE_data_meta")]
  pub meta: Meta,
  // 参考
  pub references: References,
  // 描述
  pub description: Description,
  // 问题类型 关联：CWE
  #[serde(rename = "problemtype")]
  pub problem_type: ProblemType,
}
/// This is reference data in the form of URLs or file objects (uuencoded and embedded within the JSON file, exact format to be decided, e.g. we may require a compressed format so the objects require unpacking before they are "dangerous").
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct References {
  pub reference_data: Vec<Reference>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Reference {
  pub url: String,
  pub name: String,
  pub refsource: String,
  pub tags: Vec<String>,
}
/// This is problem type information (e.g. CWE identifier).
///
/// Must contain: At least one entry, can be text, OWASP, CWE, please note that while only one is required you can use more than one (or indeed all three) as long as they are correct). (CNA requirement: [PROBLEMTYPE])
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProblemType {
  #[serde(rename = "problemtype_data")]
  problem_type_data: Vec<ProblemTypeDataItem>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProblemTypeDataItem {
  pub description: Vec<ProblemTypeDescription>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProblemTypeDescription {
  pub lang: String,
  pub value: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Description {
  pub description_data: Vec<DescriptionData>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DescriptionData {
  pub lang: String,
  pub value: String,
}
/// This is metadata about the CVE ID such as the CVE ID, who requested it, who assigned it, when it was requested, when it was assigned, the current state (PUBLIC, REJECT, etc.) and so on.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Meta {
  /// CVE-YEAR-NNNNNNN - the CVE ID in the format listed in http://cve.mitre.org/cve/identifiers/syntaxchange.html#new
  #[serde(rename = "ID")]
  id: String,
  /// Assigner ID - the assigner of the CVE (email address)
  #[serde(rename = "ASSIGNER")]
  assigner: String,
}
