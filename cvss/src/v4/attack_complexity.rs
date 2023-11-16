//! ### Attack Complexity (AC)
//! This metric captures measurable actions that must be taken by the attacker to actively evade or circumvent **existing built-in security-enhancing conditions** in order to obtain a working exploit. These are conditions whose primary purpose is to increase security and/or increase exploit engineering complexity. A vulnerability exploitable without a target-specific variable has a lower complexity than a vulnerability that would require non-trivial customization. This metric is meant to capture security mechanisms utilized by the vulnerable system, and does not relate to the amount of time or attempts it would take for an attacker to succeed, e.g. a race condition. If the attacker does not take action to overcome these conditions, the attack will always fail.
//!
//! The evasion or satisfaction of authentication mechanisms or requisites is included in the Privileges Required assessment and is **not** considered here as a factor of relevance for Attack Complexity.
//!
//! **Table 2: Attack Complexity**
//!
//! | **Metric Value** | **Description** |
//! | --- | --- |
//! | Low (L) | The attacker must take no measurable action to exploit the vulnerability. The attack requires no target-specific circumvention to exploit the vulnerability. An attacker can expect repeatable success against the vulnerable system. |
//! | High (H) | The successful attack depends on the evasion or circumvention of security-enhancing techniques in place that would otherwise hinder the attack. These include: Evasion of exploit mitigation techniques. The attacker must have additional methods available to bypass security measures in place. For example, circumvention of **address space randomization (ASLR) or data execution prevention (DEP)** must be performed for the attack to be successful. Obtaining target-specific secrets. The attacker must gather some **target-specific secret** before the attack can be successful. A secret is any piece of information that cannot be obtained through any amount of reconnaissance. To obtain the secret the attacker must perform additional attacks or break otherwise secure measures (e.g. knowledge of a secret key may be needed to break a crypto channel). This operation must be performed for each attacked target. |
//!
//! As described in Section 2.1, detailed knowledge of the vulnerable system is outside the scope of Attack Complexity. Refer to that section for additional guidance when scoring Attack Complexity when target-specific attack mitigation is present.
use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV3, Worth};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Attack Complexity (AC) 攻击复杂度
///
/// 攻击复杂度为攻击者无法控制的条件，这些条件必须存在才能攻击脆弱组件。
/// 如下文所述，这些条件可能需要预先收集有关目标或系统的配置或计算异常等更多信息。
///
/// > The Attack Complexity metric describes the conditions beyond the attacker's control that must
/// > exist in order to exploit the vulnerability. As described below, such conditions may require
/// > the collection of more information about the target, the presence of certain system
/// > configuration settings, or computational exceptions.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackComplexityType {
  /// High(H) 高复杂度
  ///
  /// 攻击无法随意完成，攻击者在攻击成功之前，需要对脆弱组件投入大量的准备。
  High,
  /// Low(L) 低复杂度
  ///
  /// 攻击者可以随意攻击，不存在惩罚机制。
  Low,
}

impl AttackComplexityType {
  #[allow(dead_code)]
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
impl Display for AttackComplexityType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}
impl Metric for AttackComplexityType {
  const TYPE: MetricType = MetricType::V3(MetricTypeV3::AC);

  fn help(&self) -> Help {
    match self {
      AttackComplexityType::High => {Help{ worth: Worth::Bad, des: "The successful attack depends on the evasion or circumvention of security-enhancing techniques in place that would otherwise hinder the attack. These include: Evasion of exploit mitigation techniques, for example, circumvention of address space randomization (ASLR) or data execution prevention (DEP) must be performed for the attack to be successful; Obtaining target-specific secrets. The attacker must gather some target-specific secret before the attack can be successful. A secret is any piece of information that cannot be obtained through any amount of reconnaissance. To obtain the secret the attacker must perform additional attacks or break otherwise secure measures (e.g. knowledge of a secret key may be needed to break a crypto channel). This operation must be performed for each attacked target.".to_string() }}
      AttackComplexityType::Low => {Help{ worth: Worth::Worst, des: "The attacker must take no measurable action to exploit the vulnerability. The attack requires no target-specific circumvention to exploit the vulnerability. An attacker can expect repeatable success against the vulnerable system.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      AttackComplexityType::High => 0.44,
      AttackComplexityType::Low => 0.77,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      AttackComplexityType::High => "H",
      AttackComplexityType::Low => "L",
    }
  }
}
impl FromStr for AttackComplexityType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with(Self::name()) {
      s = s
        .strip_prefix(&format!("{}:", Self::name()))
        .unwrap_or_default()
        .to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS { value: s })?
    };
    match c {
      'L' => Ok(Self::Low),
      'H' => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
      }),
    }
  }
}
