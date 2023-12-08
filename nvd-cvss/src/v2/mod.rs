//!
//! Common Vulnerability Scoring System Version 2.0
//! =======================================================================
//!
//! Currently, IT management must identify and assess vulnerabilities across many disparate hardware and software platforms. They need to prioritize these vulnerabilities and remediate those that pose the greatest risk. But when there are so many to fix, with each being scored using different scales, how can IT managers convert this mountain of vulnerability data into actionable information? The Common Vulnerability Scoring System (CVSS) is an open framework that addresses this issue. It offers the following benefits:
//!
//! **Standardized Vulnerability Scores**:
//!
//! > When an organization normalizes vulnerability scores across all of its software and hardware platforms, it can leverage a single vulnerability management policy. This policy may be similar to a service level agreement (SLA) that states how quickly a particular vulnerability must be validated and remediated.
//!
//! **Open Framework**:
//!
//! > Users can be confused when a vulnerability is assigned an arbitrary score. "Which properties gave it that score? How does it differ from the one released yesterday?" With CVSS, anyone can see the individual characteristics used to derive a score.
//!
//! **Prioritized Risk**:
//!
//! > When the environmental score is computed, the vulnerability now becomes contextual. That is, vulnerability scores are now representative of the actual risk to an organization. Users know how important a given vulnerability is in relation to other vulnerabilities.
//!
//! * * *
//!
pub mod access_complexity;
pub mod access_vector;
pub mod authentication;
pub mod impact_metrics;

use std::fmt::{Display, Formatter};
use std::str::FromStr;
// https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator
use crate::error::{CVSSError, Result};
use crate::metric::{Metric, MetricLevelType};
use crate::severity::SeverityTypeV2;
use crate::v2::access_complexity::AccessComplexityType;
use crate::v2::access_vector::AccessVectorType;
use crate::v2::authentication::AuthenticationType;
use crate::v2::impact_metrics::{
  AvailabilityImpactType, ConfidentialityImpactType, IntegrityImpactType,
};
use crate::version::Version;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CVSS {
  // 版本
  pub version: Version,
  // 向量: CVSS:2.0/AV:L/AC:L/Au:N/C:C/I:C/A:C
  pub vector_string: String,
  // 访问向量
  pub access_vector: AccessVectorType,
  // 访问复杂性
  pub access_complexity: AccessComplexityType,
  // 认证
  pub authentication: AuthenticationType,
  // 保密性影响 (C)
  pub confidentiality_impact: ConfidentialityImpactType,
  // 完整性影响 (I)
  pub integrity_impact: IntegrityImpactType,
  // 可用性影响（A）
  pub availability_impact: AvailabilityImpactType,
  // 基础评分
  pub base_score: f32,
}
impl Display for CVSS {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "CVSS:{}/{}/{}/{}/{}/{}/{}",
      self.version,
      self.access_vector,
      self.access_complexity,
      self.authentication,
      self.confidentiality_impact,
      self.integrity_impact,
      self.availability_impact,
    )
  }
}

impl FromStr for CVSS {
  type Err = CVSSError;
  fn from_str(vector_string: &str) -> Result<Self> {
    let (version, vectors) = match vector_string.split_once('/') {
      None => {
        return Err(CVSSError::InvalidPrefix {
          value: vector_string.to_string(),
        });
      }
      Some((v, vector)) => {
        let version = Version::from_str(v).unwrap_or_default();
        (version, vector)
      }
    };
    if matches!(version, Version::None) {
      return Err(CVSSError::InvalidCVSSVersion {
        value: version.to_string(),
        expected: "2.0".to_string(),
      });
    }
    let mut vector = vectors.split('/');
    // "CVSS:2.0/AV:L/AC:M/Au:N/C:C/I:C/A:C"
    let error = CVSSError::InvalidCVSS {
      key: "CVSS:2.0".to_string(),
      value: vector_string.to_string(),
      expected: "".to_string(),
    };
    let mut cvss = CVSS {
      version,
      vector_string: vector_string.to_string(),
      access_vector: AccessVectorType::from_str(vector.next().ok_or(&error)?)?,
      access_complexity: AccessComplexityType::from_str(vector.next().ok_or(&error)?)?,
      authentication: AuthenticationType::from_str(vector.next().ok_or(&error)?)?,
      confidentiality_impact: ConfidentialityImpactType::from_str(vector.next().ok_or(&error)?)?,
      integrity_impact: IntegrityImpactType::from_str(vector.next().ok_or(&error)?)?,
      availability_impact: AvailabilityImpactType::from_str(vector.next().ok_or(&error)?)?,
      base_score: 0.0,
    };
    cvss.update_score();
    Ok(cvss)
  }
}

impl CVSS {
  /// BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-0.5)*f(Impact))
  ///
  /// Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
  ///
  /// Exploitability = 20* AccessVector*AccessComplexity*Authentication
  ///
  /// f(impact)= 0 if Impact=0, 1.176 otherwise
  fn update_score(&mut self) {
    let exploit_ability_score = self.exploit_ability_score();
    let impact_score = self.impact_score();
    // f(impact)= 0 if Impact=0, 1.176 otherwise
    let impact = if impact_score == 0.0 { 0.0 } else { 1.176 };
    let base_score = ((0.6 * impact_score) + (0.4 * exploit_ability_score) - 1.5) * impact;
    self.base_score = self.round_to_1_decimal(base_score);
  }
  /// Exploitability = 20* AccessVector*AccessComplexity*Authentication
  pub fn exploit_ability_score(&self) -> f32 {
    self.round_to_1_decimal(
      20.0
        * self.access_vector.score()
        * self.access_complexity.score()
        * self.authentication.score(),
    )
  }
  /// Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
  pub fn impact_score(&self) -> f32 {
    let impact_score = (10.41
      * (1.0
        - (1.0 - self.confidentiality_impact.score())
          * (1.0 - self.integrity_impact.score())
          * (1.0 - self.availability_impact.score())))
    .min(10.0);
    self.round_to_1_decimal(impact_score)
  }
  fn round_to_1_decimal(&self, score: f32) -> f32 {
    (score * 10.0).ceil() / 10.0
  }
}

/// cvss v2
///
/// The CVSSv2 <https://www.first.org/cvss/v2/guide> scoring data, split up into Base Metrics Group (BM), Temporal Metrics Group (TM) and Environmental Metrics Group (EM).
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImpactMetricV2 {
  #[serde(default)]
  pub source: Option<String>,
  #[serde(default)]
  pub r#type: MetricLevelType,
  #[serde(alias = "cvssData")]
  pub cvss_v2: CVSS,
  // 漏洞的可利用评分
  pub exploitability_score: f32,
  // 评分
  pub impact_score: f32,
  // 评级
  #[serde(alias = "baseSeverity")]
  pub severity: SeverityTypeV2,
  pub ac_insuf_info: Option<bool>,
  pub obtain_all_privilege: bool,
  pub obtain_user_privilege: bool,
  pub obtain_other_privilege: bool,
  // 用户交互
  pub user_interaction_required: Option<bool>,
}

impl FromStr for ImpactMetricV2 {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    match CVSS::from_str(s) {
      Ok(c) => {
        let exploitability_score = c.exploit_ability_score();
        let impact_score = c.impact_score();
        let severity = SeverityTypeV2::from(c.base_score);
        Ok(Self {
          source: None,
          r#type: Default::default(),
          cvss_v2: c,
          exploitability_score,
          impact_score,
          severity,
          ac_insuf_info: None,
          obtain_all_privilege: false,
          obtain_user_privilege: false,
          obtain_other_privilege: false,
          user_interaction_required: None,
        })
      }
      Err(err) => Err(err),
    }
  }
}
