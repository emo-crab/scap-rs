//!
//! Common Vulnerability Scoring System version 3.1
//! ===============================================
//!
//!
//! CVSS Version 3.1 Release
//! ------------------------
//!
//! This page updates with each release of the CVSS standard. It is currently CVSS version 3.1, released in June 2019. If you wish to use a specific version of the Specification Document, use:
//!
//! *   [https://www.first.org/cvss/v3.1/specification-document](https://www.first.org/cvss/v3.1/specification-document) for CVSS version 3.1
//! *   [https://www.first.org/cvss/v3.0/specification-document](https://www.first.org/cvss/v3.0/specification-document) for CVSS version 3.0
//!
//! * * *
//!

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CVSSError, Result};
use crate::metric::{Metric, MetricLevelType};
use crate::severity::SeverityType;
use crate::v3::attack_complexity::AttackComplexityType;
use crate::v3::attack_vector::AttackVectorType;
use crate::v3::impact_metrics::{
  AvailabilityImpactType, ConfidentialityImpactType, Impact, IntegrityImpactType,
};
use crate::v3::privileges_required::PrivilegesRequiredType;
use crate::v3::scope::ScopeType;
use crate::v3::user_interaction::UserInteractionType;
use crate::version::Version;

pub mod attack_complexity;
pub mod attack_vector;
pub mod impact_metrics;
pub mod privileges_required;
pub mod scope;
pub mod user_interaction;

/// 2.1. Exploitability Metrics
///
/// As mentioned, the Exploitability metrics reflect the characteristics of the thing that is vulnerable, which we refer to formally as the vulnerable component. Therefore, each of the Exploitability metrics listed below should be scored relative to the vulnerable component, and reflect the properties of the vulnerability that lead to a successful attack.
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExploitAbility {
  /// [`AttackVectorType`] 访问途径（AV）
  pub attack_vector: AttackVectorType,
  /// [`AttackComplexityType`] 攻击复杂度（AC）
  pub attack_complexity: AttackComplexityType,
  /// [`PrivilegesRequiredType`] 所需权限（PR）
  pub privileges_required: PrivilegesRequiredType,
  /// [`UserInteractionType`] 用户交互（UI）
  pub user_interaction: UserInteractionType,
}

impl ExploitAbility {
  /// 8.22 × 𝐴𝑡𝑡𝑎𝑐𝑘𝑉𝑒𝑐𝑡𝑜𝑟 × 𝐴𝑡𝑡𝑎𝑐𝑘𝐶𝑜𝑚𝑝𝑙𝑒𝑥𝑖𝑡𝑦 × 𝑃𝑟𝑖𝑣𝑖𝑙𝑒𝑔𝑒𝑅𝑒𝑞𝑢𝑖𝑟𝑒𝑑 × 𝑈𝑠𝑒𝑟𝐼𝑛𝑡𝑒𝑟𝑎𝑐𝑡𝑖𝑜𝑛
  pub fn score(&self, scope_is_changed: bool) -> f32 {
    8.22
      * self.attack_vector.score()
      * self.attack_complexity.score()
      * self.user_interaction.score()
      * self.privileges_required.scoped_score(scope_is_changed)
  }
}

///
/// The Common Vulnerability Scoring System (CVSS) captures the principal technical characteristics of software, hardware and firmware vulnerabilities. Its outputs include numerical scores indicating the severity of a vulnerability relative to other vulnerabilities.
///
/// CVSS is composed of three metric groups: Base, Temporal, and Environmental. The Base Score reflects the severity of a vulnerability according to its intrinsic characteristics which are constant over time and assumes the reasonable worst case impact across different deployed environments. The Temporal Metrics adjust the Base severity of a vulnerability based on factors that change over time, such as the availability of knowledge_base code. The Environmental Metrics adjust the Base and Temporal severities to a specific computing environment. They consider factors such as the presence of mitigations in that environment.
///
/// Base Scores are usually produced by the organization maintaining the vulnerable product, or a third party scoring on their behalf. It is typical for only the Base Metrics to be published as these do not change over time and are common to all environments. Consumers of CVSS should supplement the Base Score with Temporal and Environmental Scores specific to their use of the vulnerable product to produce a severity more accurate for their organizational environment. Consumers may use CVSS information as input to an organizational vulnerability management process that also considers factors that are not part of CVSS in order to rank the threats to their technology infrastructure and make informed remediation decisions. Such factors may include: number of customers on a product line, monetary losses due to a breach, life or property threatened, or public sentiment on highly publicized vulnerabilities. These are outside the scope of CVSS.
///
/// The benefits of CVSS include the provision of a standardized vendor and platform agnostic vulnerability scoring methodology. It is an open framework, providing transparency to the individual characteristics and methodology used to derive a score.
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CVSS {
  /// Version 版本： 3.0 和 3.1
  pub version: Version,
  /// 向量: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  pub vector_string: String,
  #[serde(flatten)]
  pub exploit_ability: ExploitAbility,
  /// [`ScopeType`] 影响范围（S）
  pub scope: ScopeType,
  #[serde(flatten)]
  pub impact: Impact,
  /// 基础评分
  pub base_score: f32,
  /// [`SeverityType`] 基础评级
  pub base_severity: SeverityType,
}

impl CVSS {
  /// https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
  /// 7.1. Base Metrics Equations
  /// The Base Score formula depends on sub-formulas for Impact Sub-Score (ISS), Impact, and Exploitability, all of which are defined below:
  ///
  /// | ISS = | 1 - \[ (1 - Confidentiality) × (1 - Integrity) × (1 - Availability) \] |
  /// | --- | --- |
  /// | Impact = |  |
  /// | If Scope is Unchanged | 6.42 × ISS |
  /// | If Scope is Changed | 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)15 |
  /// | Exploitability = | 8.22 × AttackVector × AttackComplexity × |
  /// |  | PrivilegesRequired × UserInteraction |
  /// | BaseScore = |  |
  /// | If Impact \\<= 0 | 0, _else_ |
  /// | If Scope is Unchanged | Roundup (Minimum \[(Impact + Exploitability), 10\]) |
  /// | If Scope is Changed | Roundup (Minimum \[1.08 × (Impact + Exploitability), 10\]) |[](#body)
  ///
  fn base_score(&self) -> f32 {
    let exploit_ability_score = self.exploitability_score();
    let impact_score_scope = self.impact_score();
    // > BaseScore
    // If (Impact sub score <= 0)     0 else,
    // Scope Unchanged                 𝑅𝑜𝑢𝑛𝑑𝑢𝑝(𝑀𝑖𝑛𝑖𝑚𝑢𝑚[(𝐼𝑚𝑝𝑎𝑐𝑡 + 𝐸𝑥𝑝𝑙𝑜𝑖𝑡𝑎𝑏𝑖𝑙𝑖𝑡𝑦), 10])
    if impact_score_scope <= 0.0 {
      0.0
    } else if !self.scope.is_changed() {
      roundup((impact_score_scope + exploit_ability_score).min(10.0))
    } else {
      roundup((1.08 * (impact_score_scope + exploit_ability_score)).min(10.0))
    }
  }
  pub fn exploitability_score(&self) -> f32 {
    self.exploit_ability.score(self.scope.is_changed())
  }
  /// Scope Unchanged 6.42 × 𝐼𝑆𝐶Base
  /// Scope Changed 7.52 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.029] − 3.25 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.02]15
  pub fn impact_score(&self) -> f32 {
    let impact_sub_score_base = self.impact.impact_sub_score_base();

    if !self.scope.is_changed() {
      self.scope.score() * impact_sub_score_base
    } else {
      (self.scope.score() * (impact_sub_score_base - 0.029).abs())
        - (3.25 * (impact_sub_score_base - 0.02).abs().powf(15.0))
    }
  }
  pub fn builder(
    version: Version,
    exploit_ability: ExploitAbility,
    scope: ScopeType,
    impact: Impact,
  ) -> CVSSBuilder {
    CVSSBuilder::new(version, exploit_ability, scope, impact)
  }
}

impl Display for CVSS {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "CVSS:{}/{}/{}/{}/{}/{}/{}/{}/{}",
      self.version,
      self.exploit_ability.attack_vector,
      self.exploit_ability.attack_complexity,
      self.exploit_ability.privileges_required,
      self.exploit_ability.user_interaction,
      self.scope,
      self.impact.confidentiality_impact,
      self.impact.integrity_impact,
      self.impact.availability_impact
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
        expected: "3.0 or 3.1".to_string(),
      });
    }
    let mut vector = vectors.split('/');
    // "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    let error = CVSSError::InvalidCVSS {
      key: "CVSS:3.1".to_string(),
      value: vector_string.to_string(),
      expected: "".to_string(),
    };
    let exploit_ability = ExploitAbility {
      attack_vector: AttackVectorType::from_str(vector.next().ok_or(&error)?)?,
      attack_complexity: AttackComplexityType::from_str(vector.next().ok_or(&error)?)?,
      privileges_required: PrivilegesRequiredType::from_str(vector.next().ok_or(&error)?)?,
      user_interaction: UserInteractionType::from_str(vector.next().ok_or(&error)?)?,
    };
    let scope = ScopeType::from_str(vector.next().ok_or(&error)?)?;
    let impact = Impact {
      confidentiality_impact: ConfidentialityImpactType::from_str(vector.next().ok_or(&error)?)?,
      integrity_impact: IntegrityImpactType::from_str(vector.next().ok_or(&error)?)?,
      availability_impact: AvailabilityImpactType::from_str(vector.next().ok_or(&error)?)?,
    };
    let mut cvss = CVSS {
      version,
      vector_string: vector_string.to_string(),
      exploit_ability,
      scope,
      impact,
      base_score: 0.0,
      base_severity: SeverityType::None,
    };
    cvss.base_score = cvss.base_score();
    cvss.base_severity = SeverityType::from(cvss.base_score);
    cvss.vector_string = cvss.to_string();
    Ok(cvss)
  }
}

pub struct CVSSBuilder {
  /// Version 版本： 3.0 和 3.1
  pub version: Version,
  pub exploit_ability: ExploitAbility,
  /// [`ScopeType`] 影响范围（S）
  pub scope: ScopeType,
  pub impact: Impact,
}

/// CVSS Builder
impl CVSSBuilder {
  pub fn new(
    version: Version,
    exploit_ability: ExploitAbility,
    scope: ScopeType,
    impact: Impact,
  ) -> Self {
    Self {
      version,
      exploit_ability,
      scope,
      impact,
    }
  }
  pub fn build(self) -> CVSS {
    let Self {
      version,
      exploit_ability,
      scope,
      impact,
    } = self;
    let mut cvss = CVSS {
      version,
      vector_string: "".to_string(),
      exploit_ability,
      scope,
      impact,
      base_score: 0.0,
      base_severity: SeverityType::None,
    };
    cvss.vector_string = cvss.to_string();
    cvss.base_score = cvss.base_score();
    cvss.base_severity = SeverityType::from(cvss.base_score);
    cvss
  }
}

/// cvss v3
///
/// The CVSSv3 <https://www.first.org/cvss/specification-document> scoring data.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImpactMetricV3 {
  #[serde(default)]
  pub source: Option<String>,
  #[serde(default)]
  pub r#type: MetricLevelType,
  #[serde(alias = "cvssData")]
  pub cvss_v3: CVSS,
  /// 漏洞的可利用 评分
  pub exploitability_score: f32,
  /// 影响评分
  pub impact_score: f32,
}

impl FromStr for ImpactMetricV3 {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    match CVSS::from_str(s) {
      Ok(c) => {
        let exploit_ability_score = c.exploitability_score();
        let impact_score = c.impact_score();
        Ok(Self {
          source: None,
          r#type: Default::default(),
          cvss_v3: c,
          exploitability_score: exploit_ability_score,
          impact_score,
        })
      }
      Err(err) => Err(err),
    }
  }
}

/// Roundup保留小数点后一位，小数点后第二位大于零则进一。 例如, Roundup(4.02) = 4.1; 或者 Roundup(4.00) = 4.0
///
/// Where “Round up” is defined as the smallest number,
/// specified to one decimal place, that is equal to or higher than its input. For example,
/// Round up (4.02) is 4.1; and Round up (4.00) is 4.0.
///
/// 1.  `function Roundup (input):`
/// 2.  `    int_input = round_to_nearest_integer (input * 100000)`
/// 3.  `    if (int_input % 10000) == 0:`
/// 4.  `        return int_input / 100000.0`
/// 5.  `    else:`
/// 6.  `        return (floor(int_input / 10000) + 1) / 10.0`
fn roundup(input: f32) -> f32 {
  let int_input = (input * 100_000.0) as u32;
  if int_input % 10000 == 0 {
    (int_input as f32) / 100_000.0
  } else {
    let score_floor = ((int_input as f32) / 10_000.0).floor();
    (score_floor + 1.0) / 10.0
  }
}

#[cfg(test)]
mod tests {
  use crate::v3::roundup;

  #[test]
  fn roundup_test() {
    assert_eq!(roundup(4.00), 4.0);
    assert_eq!(roundup(4.02), 4.1);
    assert_eq!(roundup(0.8619848), 0.9);
    assert_eq!(roundup(0.9006104), 1.0)
  }
}
