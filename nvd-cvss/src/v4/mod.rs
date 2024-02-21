//! ![](https://www.first.org/cvss/identity/cvssv4_web.png)
//!
//! Also available [in PDF format](https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf).
//!

// https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CVSSError, Result};
use crate::metric::Metric;
use crate::severity::SeverityType;
use crate::v4::attack_complexity::AttackComplexityType;
use crate::v4::attack_requirements::AttackRequirementsType;
use crate::v4::attack_vector::AttackVectorType;
use crate::v4::constant::{
  get_eq1245_max_composed, get_eq1245_max_severity, get_eq36_max_composed, get_eq36_max_severity,
  lookup,
};
use crate::v4::environmental::{
  AvailabilityRequirements, ConfidentialityRequirements, Environmental, IntegrityRequirements,
};
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

pub mod attack_complexity;
pub mod attack_requirements;
pub mod attack_vector;
mod constant;
pub mod environmental;
pub mod exploit_maturity;
pub mod privileges_required;
pub mod subsequent_impact_metrics;
pub mod user_interaction;
pub mod vulnerable_impact_metrics;

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
    None
  }
  // EQ2: 0-(AC:L and AT:N)
  //      1-(not(AC:L and AT:N))
  fn eq2(&self) -> Option<u32> {
    if self.attack_complexity.is_low() && self.attack_requirements.is_none() {
      return Some(0);
    } else if !(self.attack_complexity.is_low() && self.attack_requirements.is_none()) {
      return Some(1);
    }
    None
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
  /// <https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator>
  /// only vector_string not version
  pub fn vector_string(vectors: &str) -> Result<Self> {
    let exploit_ability = ExploitAbility {
      attack_vector: AttackVectorType::from_str(vectors)?,
      attack_complexity: AttackComplexityType::from_str(vectors)?,
      attack_requirements: AttackRequirementsType::from_str(vectors)?,
      privileges_required: PrivilegesRequiredType::from_str(vectors)?,
      user_interaction: UserInteractionType::from_str(vectors)?,
    };
    let vulnerable_impact = VulnerableImpact {
      confidentiality_impact: VulnerableConfidentialityImpactType::from_str(vectors)?,
      integrity_impact: VulnerableIntegrityImpactType::from_str(vectors)?,
      availability_impact: VulnerableAvailabilityImpactType::from_str(vectors)?,
    };
    let subsequent_impact = SubsequentImpact {
      confidentiality_impact: SubsequentConfidentialityImpactType::from_str(vectors)?,
      integrity_impact: SubsequentIntegrityImpactType::from_str(vectors)?,
      availability_impact: SubsequentAvailabilityImpactType::from_str(vectors)?,
    };
    let exploit = ExploitMaturity::from_str(vectors).unwrap_or_default();
    let environmental = Environmental {
      confidentiality_requirements: ConfidentialityRequirements::from_str(vectors)
        .unwrap_or_default(),
      integrity_requirements: IntegrityRequirements::from_str(vectors).unwrap_or_default(),
      availability_requirements: AvailabilityRequirements::from_str(vectors).unwrap_or_default(),
    };
    Ok(CVSS {
      version: Version::V4_0,
      vector_string: format!("{}{}", Version::V4_0, vectors),
      exploit_ability,
      vulnerable_impact,
      subsequent_impact,
      exploit,
      environmental,
      base_score: 0.0,
      base_severity: SeverityType::None,
    })
  }
}

impl Display for CVSS {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "CVSS:{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
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
      self.subsequent_impact.availability_impact,
      self.environmental.confidentiality_requirements,
      self.environmental.integrity_requirements,
      self.environmental.availability_requirements,
      self.exploit
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
    let mut cvss = CVSS::vector_string(vectors)?;
    cvss.base_score = cvss.base_score();
    cvss.base_severity = SeverityType::from(cvss.base_score);
    cvss.vector_string = cvss.to_string();
    Ok(cvss)
  }
}

impl CVSS {
  fn base_score(&self) -> f32 {
    if self.subsequent_impact.all_none() && self.vulnerable_impact.all_none() {
      return 0.0;
    }
    let (eq1, eq2, eq3, eq4, eq5, eq6) = self.macro_vector();
    let mv = format!("{}{}{}{}{}{}", eq1, eq2, eq3, eq4, eq5, eq6);
    let score = lookup(&eq1, &eq2, &eq3, &eq4, &eq5, &eq6).unwrap_or(0.0);
    let mut lower = 0;
    let score_eq1_next_lower = if eq1 < 2 {
      lower += 1;
      lookup(&(eq1 + 1), &eq2, &eq3, &eq4, &eq5, &eq6)
    } else {
      None
    };
    let score_eq2_next_lower = if eq2 < 1 {
      lower += 1;
      lookup(&eq1, &(eq2 + 1), &eq3, &eq4, &eq5, &eq6)
    } else {
      None
    };
    let score_eq4_next_lower = if eq4 < 2 {
      lower += 1;
      lookup(&eq1, &eq2, &eq3, &(eq4 + 1), &eq5, &eq6)
    } else {
      None
    };
    let score_eq5_next_lower = if eq5 < 2 {
      lower += 1;
      lookup(&eq1, &eq2, &eq3, &eq4, &(eq5 + 1), &eq6)
    } else {
      None
    };
    let score_eq3eq6_next_lower = if (eq3 == 0 || eq3 == 1) && eq6 == 1 {
      lower += 1;
      lookup(&eq1, &eq2, &(eq3 + 1), &eq4, &eq5, &eq6)
    } else if eq3 == 1 && eq6 == 0 {
      lower += 1;
      lookup(&eq1, &eq2, &eq3, &eq4, &eq5, &(eq6 + 1))
    } else if eq3 == 0 && eq6 == 0 {
      // multiple path take the one with higher score
      // 如果存在多个分数，取最大的分数
      lower += 1;
      let left = lookup(&eq1, &eq2, &eq3, &eq4, &eq5, &(eq6 + 1)).unwrap_or(0.0);
      let right = lookup(&eq1, &eq2, &(eq3 + 1), &eq4, &eq5, &eq6).unwrap_or(0.0);
      let max_score = right.max(left);
      Some(max_score)
    } else {
      None
    };
    // 根据lookup获取全部矩阵，然后取分数最大的那个
    let max_vectors = self.max_vectors(mv);
    let (
      current_severity_distance_eq1,
      current_severity_distance_eq2,
      current_severity_distance_eq3eq6,
      current_severity_distance_eq4,
      current_severity_distance_eq5,
    ) = self.severity_distances(max_vectors);
    let step: f32 = 0.1;
    // # multiply by step because distance is pure
    let max_severity_eq1 = get_eq1245_max_severity(1, eq1).unwrap_or_default() * step;
    let max_severity_eq2 = get_eq1245_max_severity(2, eq2).unwrap_or_default() * step;
    let max_severity_eq3eq6 = get_eq36_max_severity(eq3, eq6).unwrap_or_default() * step;
    let max_severity_eq4 = get_eq1245_max_severity(4, eq4).unwrap_or_default() * step;
    let max_severity_eq5 = get_eq1245_max_severity(5, eq5).unwrap_or_default() * step;

    let mut normalized_severity_eq1 = 0.0;
    let mut normalized_severity_eq2 = 0.0;
    let mut normalized_severity_eq3eq6 = 0.0;
    let mut normalized_severity_eq4 = 0.0;
    let mut normalized_severity_eq5 = 0.0;

    if let Some(score_eq1_next_lower) = score_eq1_next_lower {
      let available_distance_eq1 = score - score_eq1_next_lower;
      let percent_to_next_eq1_severity = current_severity_distance_eq1 / max_severity_eq1;
      normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity;
    }
    if let Some(score_eq2_next_lower) = score_eq2_next_lower {
      let available_distance_eq2 = score - score_eq2_next_lower;
      let percent_to_next_eq2_severity = current_severity_distance_eq2 / max_severity_eq2;
      normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity
    }
    if let Some(score_eq3eq6_next_lower) = score_eq3eq6_next_lower {
      let available_distance_eq3eq6 = score - score_eq3eq6_next_lower;
      let percent_to_next_eq3eq6_severity = current_severity_distance_eq3eq6 / max_severity_eq3eq6;
      normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity;
    }
    if let Some(score_eq4_next_lower) = score_eq4_next_lower {
      let available_distance_eq4 = score - score_eq4_next_lower;
      let percent_to_next_eq4_severity = current_severity_distance_eq4 / max_severity_eq4;
      normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity
    }
    if let Some(score_eq5_next_lower) = score_eq5_next_lower {
      let available_distance_eq5 = score - score_eq5_next_lower;
      let percent_to_next_eq5_severity = current_severity_distance_eq5 / max_severity_eq5;
      normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity
    }
    let mut mean_distance = 0.0;
    if lower != 0 {
      mean_distance = (normalized_severity_eq1
        + normalized_severity_eq2
        + normalized_severity_eq3eq6
        + normalized_severity_eq4
        + normalized_severity_eq5)
        / lower as f32;
    }

    roundup(score - mean_distance)
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
    None
  }
  fn max_vectors(&self, macro_vector: String) -> Vec<String> {
    let mut vectors = vec![];
    let get_index = |index| {
      macro_vector
        .chars()
        .nth((index - 1) as usize)
        .unwrap_or_default()
        .to_digit(10)
        .unwrap_or(0)
    };
    let eq1_maxes = get_eq1245_max_composed(1, get_index(1));
    let eq2_maxes = get_eq1245_max_composed(2, get_index(2));
    let eq3_eq6_maxes = get_eq36_max_composed(get_index(3), get_index(6));
    let eq4_maxes = get_eq1245_max_composed(4, get_index(4));
    let eq5_maxes = get_eq1245_max_composed(5, get_index(5));
    // 笛卡尔积获取全部可能
    for eq1_max in eq1_maxes {
      for eq2_max in eq2_maxes.iter() {
        for eq3_eq6_max in eq3_eq6_maxes.iter() {
          for eq4_max in eq4_maxes.iter() {
            for eq5_max in eq5_maxes.iter() {
              vectors.push(format!(
                "{}{}{}{}{}",
                eq1_max, eq2_max, eq3_eq6_max, eq4_max, eq5_max
              ));
            }
          }
        }
      }
    }
    vectors
  }
  fn severity_distances(&self, vectors: Vec<String>) -> (f32, f32, f32, f32, f32) {
    // 每个都和self这个cvss的分数比较，返回第一个大于self本身的
    let mut severity_distances = vec![];
    for vector in vectors {
      let max_vector = CVSS::vector_string(&vector);
      if let Ok(max_vector) = max_vector {
        let av = self.exploit_ability.attack_vector.score()
          - max_vector.exploit_ability.attack_vector.score();
        let pr = self.exploit_ability.privileges_required.score()
          - max_vector.exploit_ability.privileges_required.score();
        let ui = self.exploit_ability.user_interaction.score()
          - max_vector.exploit_ability.user_interaction.score();

        let ac = self.exploit_ability.attack_complexity.score()
          - max_vector.exploit_ability.attack_complexity.score();
        let at = self.exploit_ability.attack_requirements.score()
          - max_vector.exploit_ability.attack_requirements.score();

        let vc = self.vulnerable_impact.confidentiality_impact.score()
          - max_vector.vulnerable_impact.confidentiality_impact.score();
        let vi = self.vulnerable_impact.integrity_impact.score()
          - max_vector.vulnerable_impact.integrity_impact.score();
        let va = self.vulnerable_impact.availability_impact.score()
          - max_vector.vulnerable_impact.availability_impact.score();

        let sc = self.subsequent_impact.confidentiality_impact.score()
          - max_vector.subsequent_impact.confidentiality_impact.score();
        let si = self.subsequent_impact.integrity_impact.score()
          - max_vector.subsequent_impact.integrity_impact.score();
        let sa = self.subsequent_impact.availability_impact.score()
          - max_vector.subsequent_impact.availability_impact.score();

        let cr = self.environmental.confidentiality_requirements.score()
          - max_vector
            .environmental
            .confidentiality_requirements
            .score();
        let ir = self.environmental.integrity_requirements.score()
          - max_vector.environmental.integrity_requirements.score();
        let ar = self.environmental.availability_requirements.score()
          - max_vector.environmental.availability_requirements.score();
        let all_severity_distances = vec![av, pr, ui, ac, at, vc, vi, va, sc, si, sa, cr, ir, ar];
        // # if any is less than zero this is not the right max
        if all_severity_distances.iter().any(|m| m < &0.0) {
          continue;
        }
        severity_distances = all_severity_distances;
        break;
        // # if multiple maxes exist to reach it it is enough the first one
      }
    }
    // 以前pop是从末尾开始的，所以要先倒过来
    severity_distances.reverse();
    let (av, pr, ui, ac, at, vc, vi, va, sc, si, sa, cr, ir, ar) = (
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
      severity_distances.pop().unwrap_or_default(),
    );
    let current_severity_distance_eq1 = av + pr + ui;
    let current_severity_distance_eq2 = ac + at;
    let current_severity_distance_eq3eq6 = vc + vi + va + cr + ir + ar;
    let current_severity_distance_eq4 = sc + si + sa;
    let current_severity_distance_eq5 = 0.0;
    (
      current_severity_distance_eq1,
      current_severity_distance_eq2,
      current_severity_distance_eq3eq6,
      current_severity_distance_eq4,
      current_severity_distance_eq5,
    )
  }
  fn macro_vector(&self) -> (u32, u32, u32, u32, u32, u32) {
    let eq1 = self.exploit_ability.eq1().unwrap_or_default();
    let eq2 = self.exploit_ability.eq2().unwrap_or_default();
    let eq3 = self.vulnerable_impact.eq3().unwrap_or_default();
    let eq4 = self.subsequent_impact.eq4().unwrap_or_default();
    let eq5 = self.exploit.eq5().unwrap_or_default();
    let eq6 = self.eq6().unwrap_or_default();
    (eq1, eq2, eq3, eq4, eq5, eq6)
  }
}
/// Roundup保留小数点后一位，小数点后第二位四舍五入。 例如, Roundup(4.02) = 4.0; 或者 Roundup(4.00) = 4.0
fn roundup(input: f32) -> f32 {
  let int_input = (input * 100.0) as u32;
  if int_input % 10 < 5 {
    (int_input / 10) as f32 / 10.0
  } else {
    let score_floor = ((int_input as f32) / 10.0).floor();
    (score_floor + 1.0) / 10.0
  }
}
#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::str::FromStr;

  use crate::v4::{roundup, CVSS};

  #[test]
  fn roundup_test() {
    assert_eq!(roundup(0.12000), 0.1);
    assert_eq!(roundup(0.15000), 0.2);
    assert_eq!(roundup(0.94900), 0.9);
  }
  #[test]
  fn cvss_score_test() {
    let vs_map: HashMap<&'static str, f32> = HashMap::from_iter([
      (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        10.0,
      ),
      (
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
        9.4,
      ),
      (
        "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
        9.0,
      ),
      (
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
        8.9,
      ),
      (
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
        7.3,
      ),
      (
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
        6.1,
      ),
      (
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A",
        2.4,
      ),
      (
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:N/SA:H/E:A",
        2.0,
      ),
      (
        "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:N/SA:H/E:P/CR:H/IR:M/AR:L",
        0.9,
      ),
    ]);
    for (k, v) in vs_map.iter() {
      let cvss = CVSS::from_str(k).unwrap();
      assert_eq!(cvss.base_score, *v)
    }
  }
}
