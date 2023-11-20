//! ![](https://www.first.org/cvss/identity/cvssv4_web.png)
//!
//! Also available [in PDF format](https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf).
//!

// https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js

use crate::error::{CVSSError, Result};
use crate::metric::Metric;
use crate::severity::SeverityType;
use crate::v4::attack_complexity::AttackComplexityType;
use crate::v4::attack_requirements::AttackRequirementsType;
use crate::v4::attack_vector::AttackVectorType;
use crate::v4::constant::{get_eq1245_max_composed, CVSS_LOOKUP, get_eq36_max_composed};
use crate::v4::environmental::Environmental;
use crate::v4::exploit_maturity::ExploitMaturity;
use crate::v4::privileges_required::PrivilegesRequiredType;
use crate::v4::subsequent_impact_metrics::{
  SubsequentAvailabilityImpactType, SubsequentConfidentialityImpactType, SubsequentImpact,
  SubsequentIntegrityImpactType,
};
use crate::v4::user_interaction::UserInteractionType;
use crate::v4::vulnerable_impact_metrics::{
  VulnerableAvailabilityImpactType, VulnerableConfidentialityImpactType, VulnerableImpact,
  VulnerableIntegrityImpactType,
};
use crate::version::Version;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

mod attack_complexity;
mod attack_requirements;
mod attack_vector;
mod constant;
mod environmental;
mod exploit_maturity;
mod privileges_required;
mod subsequent_impact_metrics;
mod user_interaction;
mod vulnerable_impact_metrics;

/// 2.1. Exploitability Metrics
///
/// As mentioned, the Exploitability metrics reflect the characteristics of the thing that is vulnerable, which we refer to formally as the vulnerable component. Therefore, each of the Exploitability metrics listed below should be scored relative to the vulnerable component, and reflect the properties of the vulnerability that lead to a successful attack.
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct ExploitAbility {
  /// [`AttackVectorType`] 访问途径（AV）
  pub attack_vector: AttackVectorType,
  /// [`AttackComplexityType`] 攻击复杂度（AC）
  pub attack_complexity: AttackComplexityType,
  /// [`AttackRequirementsType`] 攻击要求（AT）
  pub attack_requirements: AttackRequirementsType,
  /// [`PrivilegesRequiredType`] 所需权限（PR）
  pub privileges_required: PrivilegesRequiredType,
  /// [`UserInteractionType`] 用户交互（UI）
  pub user_interaction: UserInteractionType,
}

impl ExploitAbility {
  /// 8.22 × 𝐴𝑡𝑡𝑎𝑐𝑘𝑉𝑒𝑐𝑡𝑜𝑟 × 𝐴𝑡𝑡𝑎𝑐𝑘𝐶𝑜𝑚𝑝𝑙𝑒𝑥𝑖𝑡𝑦 × 𝑃𝑟𝑖𝑣𝑖𝑙𝑒𝑔𝑒𝑅𝑒𝑞𝑢𝑖𝑟𝑒𝑑 × 𝑈𝑠𝑒𝑟𝐼𝑛𝑡𝑒𝑟𝑎𝑐𝑡𝑖𝑜𝑛
  pub fn score(&self) -> f32 {
    self.attack_vector.score()
      + self.attack_complexity.score()
      + self.user_interaction.score()
      + self.privileges_required.score()
  }
  // EQ1: 0-AV:N and PR:N and UI:N
  //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
  //      2-AV:P or not(AV:N or PR:N or UI:N)
  fn eq1(&self) -> Option<u32> {
    if self.attack_vector.is_network()
      && self.privileges_required.is_none()
      && self.user_interaction.is_none()
    {
      // 0: ["AV:N/PR:N/UI:N/"],
      return Some(0);
    } else if (self.attack_vector.is_network()
      || self.privileges_required.is_none()
      || self.user_interaction.is_none())
      && !(self.attack_vector.is_network()
        && self.privileges_required.is_none()
        && self.user_interaction.is_none())
      && !(self.attack_vector.is_physical())
    {
      // 1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
      return Some(1);
    } else if self.attack_vector.is_physical()
      || !(self.attack_vector.is_network()
        || self.privileges_required.is_none()
        || self.user_interaction.is_none())
    {
      // 2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
      return Some(2);
    }
    return None;
  }
  // EQ2: 0-(AC:L and AT:N)
  //      1-(not(AC:L and AT:N))
  fn eq2(&self) -> Option<u32> {
    if self.attack_complexity.is_low() && self.attack_requirements.is_none() {
      return Some(0);
    } else if !(self.attack_complexity.is_low() && self.attack_requirements.is_none()) {
      return Some(1);
    }
    return None;
  }
}

///
/// The Common Vulnerability Scoring System (CVSS) captures the principal technical characteristics of software, hardware and firmware vulnerabilities. Its outputs include numerical scores indicating the severity of a vulnerability relative to other vulnerabilities.
///
/// CVSS is composed of three metric groups: Base, Temporal, and Environmental. The Base Score reflects the severity of a vulnerability according to its intrinsic characteristics which are constant over time and assumes the reasonable worst case impact across different deployed environments. The Temporal Metrics adjust the Base severity of a vulnerability based on factors that change over time, such as the availability of exploit code. The Environmental Metrics adjust the Base and Temporal severities to a specific computing environment. They consider factors such as the presence of mitigations in that environment.
///
/// Base Scores are usually produced by the organization maintaining the vulnerable product, or a third party scoring on their behalf. It is typical for only the Base Metrics to be published as these do not change over time and are common to all environments. Consumers of CVSS should supplement the Base Score with Temporal and Environmental Scores specific to their use of the vulnerable product to produce a severity more accurate for their organizational environment. Consumers may use CVSS information as input to an organizational vulnerability management process that also considers factors that are not part of CVSS in order to rank the threats to their technology infrastructure and make informed remediation decisions. Such factors may include: number of customers on a product line, monetary losses due to a breach, life or property threatened, or public sentiment on highly publicized vulnerabilities. These are outside the scope of CVSS.
///
/// The benefits of CVSS include the provision of a standardized vendor and platform agnostic vulnerability scoring methodology. It is an open framework, providing transparency to the individual characteristics and methodology used to derive a score.
///
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct CVSS {
  /// Version 版本： 4.0
  pub version: Version,
  /// 向量: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
  pub vector_string: String,
  #[serde(flatten)]
  pub exploit_ability: ExploitAbility,
  #[serde(flatten)]
  pub vulnerable_impact: VulnerableImpact,
  #[serde(flatten)]
  pub subsequent_impact: SubsequentImpact,
  pub exploit: ExploitMaturity,
  #[serde(flatten)]
  pub environmental: Environmental,
  /// 基础评分
  pub base_score: f32,
  /// [`SeverityType`] 基础评级
  pub base_severity: SeverityType,
}

impl CVSS {
  /// https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator

  pub fn builder(
    version: Version,
    exploit_ability: ExploitAbility,
    vulnerable_impact: VulnerableImpact,
    subsequent_impact: SubsequentImpact,
  ) -> CVSSBuilder {
    CVSSBuilder::new(
      version,
      exploit_ability,
      vulnerable_impact,
      subsequent_impact,
    )
  }
}

impl Display for CVSS {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "CVSS:{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
      self.version,
      self.exploit_ability.attack_vector,
      self.exploit_ability.attack_complexity,
      self.exploit_ability.attack_requirements,
      self.exploit_ability.privileges_required,
      self.exploit_ability.user_interaction,
      self.vulnerable_impact.confidentiality_impact,
      self.vulnerable_impact.integrity_impact,
      self.vulnerable_impact.availability_impact,
      self.subsequent_impact.confidentiality_impact,
      self.subsequent_impact.integrity_impact,
      self.subsequent_impact.availability_impact
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
        expected: "4.0".to_string(),
      });
    }
    let mut vector = vectors.split('/');
    // "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    let error = CVSSError::InvalidCVSS {
      key: "CVSS:4.0".to_string(),
      value: vector_string.to_string(),
      expected: "".to_string(),
    };
    let exploit_ability = ExploitAbility {
      attack_vector: AttackVectorType::from_str(vector.next().ok_or(&error)?)?,
      attack_complexity: AttackComplexityType::from_str(vector.next().ok_or(&error)?)?,
      attack_requirements: AttackRequirementsType::from_str(vector.next().ok_or(&error)?)?,
      privileges_required: PrivilegesRequiredType::from_str(vector.next().ok_or(&error)?)?,
      user_interaction: UserInteractionType::from_str(vector.next().ok_or(&error)?)?,
    };
    let vulnerable_impact = VulnerableImpact {
      confidentiality_impact: VulnerableConfidentialityImpactType::from_str(
        vector.next().ok_or(&error)?,
      )?,
      integrity_impact: VulnerableIntegrityImpactType::from_str(vector.next().ok_or(&error)?)?,
      availability_impact: VulnerableAvailabilityImpactType::from_str(
        vector.next().ok_or(&error)?,
      )?,
    };
    let subsequent_impact = SubsequentImpact {
      confidentiality_impact: SubsequentConfidentialityImpactType::from_str(
        vector.next().ok_or(&error)?,
      )?,
      integrity_impact: SubsequentIntegrityImpactType::from_str(vector.next().ok_or(&error)?)?,
      availability_impact: SubsequentAvailabilityImpactType::from_str(
        vector.next().ok_or(&error)?,
      )?,
    };
    let mut cvss = CVSS {
      version,
      vector_string: vector_string.to_string(),
      exploit_ability,
      subsequent_impact,
      vulnerable_impact,
      base_score: 0.0,
      base_severity: SeverityType::None,
      exploit: ExploitMaturity::default(),
      environmental: Environmental::default(),
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
  /// [`VulnerableImpact`] 缺陷系统（Vulnerable System）
  pub vulnerable_impact: VulnerableImpact,
  /// [`SubsequentImpact`] 后续系统（Subsequent System）
  pub subsequent_impact: SubsequentImpact,
}
/// CVSS Builder
impl CVSSBuilder {
  pub fn new(
    version: Version,
    exploit_ability: ExploitAbility,
    vulnerable_impact: VulnerableImpact,
    subsequent_impact: SubsequentImpact,
  ) -> Self {
    Self {
      version,
      exploit_ability,
      vulnerable_impact,
      subsequent_impact,
    }
  }
  pub fn build(self) -> CVSS {
    let Self {
      version,
      exploit_ability,
      vulnerable_impact,
      subsequent_impact,
    } = self;
    let mut cvss = CVSS {
      version,
      vector_string: "".to_string(),
      exploit_ability,
      vulnerable_impact,
      subsequent_impact,
      exploit: ExploitMaturity::default(),
      environmental: Environmental::default(),
      base_score: 0.0,
      base_severity: SeverityType::None,
    };
    cvss.vector_string = cvss.to_string();
    cvss.base_score = cvss.base_score();
    cvss.base_severity = SeverityType::from(cvss.base_score);
    cvss
  }
}

impl CVSS {
  fn base_score(&self) -> f32 {
    if self.subsequent_impact.all_none() && self.vulnerable_impact.all_none() {
      return 0.0;
    }
    let (eq1, eq2, eq3, eq4, eq5, eq6) = self.macro_vector();
    let mv = format!("{}{}{}{}{}{}", eq1, eq2, eq3, eq4, eq5, eq6);
    let score = self
      .lookup(&eq1, &eq2, &eq3, &eq4, &eq5, &eq6)
      .unwrap_or(0.0)
      .clone();
    println!("{:?}", score);
    let mut lower = 0;
    let score_eq1_next_lower = if eq1 < 2 {
      lower = lower + 1;
      self.lookup(&(eq1 + 1), &eq2, &eq3, &eq4, &eq5, &eq6)
    } else {
      None
    };
    let score_eq2_next_lower = if eq2 < 1 {
      lower = lower + 1;
      self.lookup(&eq1, &(eq2 + 1), &eq3, &eq4, &eq5, &eq6)
    } else {
      None
    };
    let score_eq4_next_lower = if eq4 < 2 {
      lower = lower + 1;
      self.lookup(&eq1, &eq2, &eq3, &(eq4 + 1), &eq5, &eq6)
    } else {
      None
    };
    let score_eq5_next_lower = if eq5 < 2 {
      lower = lower + 1;
      self.lookup(&eq1, &eq2, &eq3, &eq4, &(eq5 + 1), &eq6)
    } else {
      None
    };
    let score_eq3eq6_next_lower = if (eq3 == 1 && eq6 == 1) || (eq3 == 0 && eq6 == 1) {
      lower = lower + 1;
      self.lookup(&eq1, &eq2, &(eq3 + 1), &eq4, &eq5, &eq6)
    } else if eq3 == 1 && eq6 == 0 {
      lower = lower + 1;
      self.lookup(&eq1, &eq2, &eq3, &eq4, &eq5, &(eq6 + 1))
    } else if eq3 == 0 && eq6 == 0 {
      // multiple path take the one with higher score
      // 如果存在多个分数，取最大的分数
      lower = lower + 1;
      let left = self
        .lookup(&eq1, &eq2, &eq3, &eq4, &eq5, &(eq6 + 1))
        .unwrap_or(0.0);
      let right = self
        .lookup(&eq1, &eq2, &(eq3 + 1), &eq4, &eq5, &eq6)
        .unwrap_or(0.0);
      let max_score = right.max(left);
      Some(max_score)
    } else {
      None
    };
    println!(
      "{:?} {:?} {:?} {:?} {:?}",
      score_eq1_next_lower,
      score_eq2_next_lower,
      score_eq3eq6_next_lower,
      score_eq4_next_lower,
      score_eq5_next_lower
    );
    self.max_vectors(mv);
    let current_severity_distance_eq1 = self.exploit_ability.score();
    score
  }
  // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
  //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]
  fn eq6(&self) -> Option<u32> {
    if (self.environmental.confidentiality_requirements.is_high()
      && self.vulnerable_impact.confidentiality_impact.is_high())
      || (self.environmental.integrity_requirements.is_high()
        && self.vulnerable_impact.integrity_impact.is_high())
      || (self.environmental.availability_requirements.is_high()
        && self.vulnerable_impact.availability_impact.is_high())
    {
      return Some(0);
    } else if !(self.vulnerable_impact.confidentiality_impact.is_high()
      || (self.environmental.integrity_requirements.is_high()
        && self.vulnerable_impact.integrity_impact.is_high())
      || (self.environmental.availability_requirements.is_high()
        && self.vulnerable_impact.availability_impact.is_high()))
    {
      return Some(1);
    }
    return None;
  }
  fn max_vectors(&self, macro_vector: String) {
    let mut v = vec![];
    let mut mv = macro_vector.as_mut_vec().sli
    for (i, c) in macro_vector.chars().enumerate() {
      let index = c.to_digit(10).unwrap_or(0);
      let eq1245_max_composed = get_eq1245_max_composed((i+1) as u32, index);
      let eq36_max_composed = get_eq36_max_composed((i+1) as u32, index);
      println!("{:?} {:?}", eq1245_max_composed,eq36_max_composed);
      v.push(index);
    }
  }
  fn macro_vector(&self) -> (u32, u32, u32, u32, u32, u32) {
    let eq1 = self.exploit_ability.eq1().unwrap_or_default();
    let eq2 = self.exploit_ability.eq2().unwrap_or_default();
    let eq3 = self.vulnerable_impact.eq3().unwrap_or_default();
    let eq4 = self.subsequent_impact.eq4().unwrap_or_default();
    let eq5 = self.exploit.eq5().unwrap_or_default();
    let eq6 = self.eq6().unwrap_or_default();
    return (eq1, eq2, eq3, eq4, eq5, eq6);
  }
  fn lookup(
    &self,
    eq1: &u32,
    eq2: &u32,
    eq3: &u32,
    eq4: &u32,
    eq5: &u32,
    eq6: &u32,
  ) -> Option<f32> {
    let mv = format!("{}{}{}{}{}{}", eq1, eq2, eq3, eq4, eq5, eq6);
    CVSS_LOOKUP.get(&mv).and_then(|v| Some(v.clone()))
  }
}

impl CVSS {}
#[cfg(test)]
mod tests {
  use crate::v4::CVSS;
  use std::str::FromStr;
  #[test]
  fn cvss_test() {
    let cvss =
      CVSS::from_str("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H").unwrap();
    println!("{:?}", cvss);
  }
}
