//! impact
use cvss::error::{CVSSError, Result};
use cvss::severity::SeverityTypeV2;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// This is impact type information (e.g. a text description, CVSSv2, CVSSv3, etc.).
///
/// Must contain: At least one entry, can be text, CVSSv2, CVSSv3, others may be added
///
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase"), deny_unknown_fields)]
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
/// The CVSSv2 <https://www.first.org/cvss/v2/guide> scoring data, split up into Base Metrics Group (BM), Temporal Metrics Group (TM) and Environmental Metrics Group (EM).
///
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase"), deny_unknown_fields)]
pub struct ImpactMetricV2 {
  pub cvss_v2: cvss::v2::CVSS,
  // 漏洞的可利用评分
  pub exploitability_score: f32,
  // 评分
  pub impact_score: f32,
  // 评级
  pub severity: SeverityTypeV2,
  pub ac_insuf_info: Option<bool>,
  pub obtain_all_privilege: bool,
  pub obtain_user_privilege: bool,
  pub obtain_other_privilege: bool,
  // 用户交互
  pub user_interaction_required: Option<bool>,
}
/// cvss v3
///
/// The CVSSv3 <https://www.first.org/cvss/specification-document> scoring data.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase"), deny_unknown_fields)]
pub struct ImpactMetricV3 {
  pub cvss_v3: cvss::v3::CVSS,
  /// 漏洞的可利用 评分
  pub exploitability_score: f32,
  /// 影响评分
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
