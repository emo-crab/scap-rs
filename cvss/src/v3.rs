use crate::error::{CVSSError, Result};
use crate::metric::Metric;
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
use std::str::FromStr;

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
  fn update_severity(&mut self) {
    self.base_severity = SeverityType::from(self.base_score)
  }
  // https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
  fn update_score(&mut self) {
    let exploit_ability_score = self.exploit_ability_score();
    let impact_score_scope = self.impact_score();

    // > BaseScore
    // If (Impact sub score <= 0)     0 else,
    // Scope Unchanged                 𝑅𝑜𝑢𝑛𝑑𝑢𝑝(𝑀𝑖𝑛𝑖𝑚𝑢𝑚[(𝐼𝑚𝑝𝑎𝑐𝑡 + 𝐸𝑥𝑝𝑙𝑜𝑖𝑡𝑎𝑏𝑖𝑙𝑖𝑡𝑦), 10])
    let base_score = if impact_score_scope < 0.0 {
      0.0
    } else if !self.scope.is_changed() {
      self.roundup((impact_score_scope + exploit_ability_score).min(10.0))
    } else {
      self.roundup((1.08 * (impact_score_scope + exploit_ability_score)).min(10.0))
    };
    self.base_score = base_score;
  }
  // Roundup保留小数点后一位，小数点后第二位大于零则进一。 例如, Roundup(4.02) = 4.1; 或者 Roundup(4.00) = 4.0
  /// Where “Round up” is defined as the smallest number,
  /// specified to one decimal place, that is equal to or higher than its input. For example,
  /// Round up (4.02) is 4.1; and Round up (4.00) is 4.0.
  fn roundup(&self, base_score: f32) -> f32 {
    let score_int = (base_score * 100_000.0) as u32;
    if score_int % 10000 == 0 {
      (score_int as f32) / 100_000.0
    } else {
      let score_floor = ((score_int as f32) / 10_000.0).floor();
      (score_floor + 1.0) / 10.0
    }
  }
  /// 8.22 × 𝐴𝑡𝑡𝑎𝑐𝑘𝑉𝑒𝑐𝑡𝑜𝑟 × 𝐴𝑡𝑡𝑎𝑐𝑘𝐶𝑜𝑚𝑝𝑙𝑒𝑥𝑖𝑡𝑦 × 𝑃𝑟𝑖𝑣𝑖𝑙𝑒𝑔𝑒𝑅𝑒𝑞𝑢𝑖𝑟𝑒𝑑 × 𝑈𝑠𝑒𝑟𝐼𝑛𝑡𝑒𝑟𝑎𝑐𝑡𝑖𝑜𝑛
  pub fn exploit_ability_score(&self) -> f32 {
    self.roundup(
      8.22
        * self.attack_vector.score()
        * self.attack_complexity.score()
        * self.user_interaction.score()
        * self
          .privileges_required
          .scoped_score(self.scope.is_changed()),
    )
  }
  /// 𝐼𝑆𝐶𝐵𝑎𝑠𝑒 = 1 − [(1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐶𝑜𝑛𝑓) × (1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐼𝑛𝑡𝑒𝑔) × (1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐴𝑣𝑎𝑖𝑙)]
  fn impact_sub_score(&self) -> f32 {
    let c_score = self.confidentiality_impact.score();
    let i_score = self.confidentiality_impact.score();
    let a_score = self.availability_impact.score();
    1.0 - ((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score)).abs()
  }
  /// Scope Unchanged 6.42 × 𝐼𝑆𝐶Base
  /// Scope Changed 7.52 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.029] − 3.25 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.02]15
  pub fn impact_score(&self) -> f32 {
    let impact_sub_score = self.impact_sub_score();
    let impact_score = if !self.scope.is_changed() {
      self.scope.score() * impact_sub_score
    } else {
      (self.scope.score() * (impact_sub_score - 0.029).abs())
        - (3.25 * (impact_sub_score - 0.02).abs().powf(15.0))
    };
    self.roundup(impact_score)
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
