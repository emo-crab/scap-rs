use std::str::FromStr;
// https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
use crate::error::{CVSSError, Result};
use crate::v3::attack_complexity::AttackComplexityType;
use crate::v3::attack_vector::AttackVectorType;
use crate::v3::impact_metrics::{
  AvailabilityImpactType, ConfidentialityImpactType, IntegrityImpactType,
};
use crate::v3::privileges_required::PrivilegesRequiredType;
use crate::v3::scope::ScopeType;
use crate::v3::severity::SeverityType;
use crate::v3::user_interaction::UserInteractionType;
use crate::version::Version;
use serde::{Deserialize, Serialize};

pub mod attack_complexity;
pub mod attack_vector;
pub mod impact_metrics;
pub mod privileges_required;
pub mod scope;
pub mod severity;
pub mod user_interaction;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CVSS {
  // 版本： 3.0 和 3.1
  pub version: Version,
  // 向量: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  pub vector_string: String,
  // 访问途径（AV）
  pub attack_vector: AttackVectorType,
  // 攻击复杂度（AC）
  pub attack_complexity: AttackComplexityType,
  // 所需权限（PR）
  pub privileges_required: PrivilegesRequiredType,
  // 用户交互（UI）
  pub user_interaction: UserInteractionType,
  // 影响范围（S）
  pub scope: ScopeType,
  // 机密性影响（C）
  pub confidentiality_impact: ConfidentialityImpactType,
  // 完整性影响（I）
  pub integrity_impact: IntegrityImpactType,
  // 可用性影响（A）
  pub availability_impact: AvailabilityImpactType,
  // 基础评分
  pub base_score: f32,
  // 基础评级
  pub base_severity: SeverityType,
}

impl CVSS {
  // https://nvd.nist.gov/vuln-metrics/cvss
  fn update_severity(&self) {}
  fn update_score(&mut self) {
    self.base_score = 0 as f32;
  }
}
impl FromStr for CVSS {
  type Err = CVSSError;
  fn from_str(vector_string: &str) -> Result<Self> {
    let (version, vectors) = match vector_string.split_once('/') {
      None => {
        return Err(CVSSError::InvalidPrefix {
          value: vector_string.to_string(),
        })
      }
      Some((v, vector)) => {
        let version = Version::from_str(v).unwrap_or_default();
        (version, vector)
      }
    };
    if matches!(version, Version::None) {
      return Err(CVSSError::InvalidCVSSVersion {
        value: version.to_string(),
        expected: "2.0, 3.0 or 3.1".to_string(),
      });
    }
    let mut vector = vectors.split('/');
    // "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    let error = CVSSError::InvalidCVSS {
      value: vector_string.to_string(),
      scope: "CVSS parser".to_string(),
    };
    let mut cvss = CVSS {
      version,
      vector_string: vector_string.to_string(),
      attack_vector: AttackVectorType::from_str(vector.next().ok_or(&error)?)?,
      attack_complexity: AttackComplexityType::from_str(vector.next().ok_or(&error)?)?,
      privileges_required: PrivilegesRequiredType::from_str(vector.next().ok_or(&error)?)?,
      user_interaction: UserInteractionType::from_str(vector.next().ok_or(&error)?)?,
      scope: ScopeType::from_str(vector.next().ok_or(&error)?)?,
      confidentiality_impact: ConfidentialityImpactType::from_str(vector.next().ok_or(&error)?)?,
      integrity_impact: IntegrityImpactType::from_str(vector.next().ok_or(&error)?)?,
      availability_impact: AvailabilityImpactType::from_str(vector.next().ok_or(&error)?)?,
      base_score: 0.0,
      base_severity: SeverityType::None,
    };
    cvss.update_score();
    cvss.update_severity();
    Ok(cvss)
  }
}
