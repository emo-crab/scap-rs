//! ### 2.1.2. Attack Complexity (AC)
//!
//! This metric describes the conditions beyond the attacker’s control that must exist in order to exploit the vulnerability. As described below, such conditions may require the collection of more information about the target, or computational exceptions. Importantly, the assessment of this metric excludes any requirements for user interaction in order to exploit the vulnerability (such conditions are captured in the User Interaction metric). If a specific configuration is required for an attack to succeed, the Base metrics should be scored assuming the vulnerable component is in that configuration. The Base Score is greatest for the least complex attacks. The list of possible values is presented in Table 2.
//!
//! **Table 2: Attack Complexity**
//!
//! | Metric Value | Description |
//! | --- | --- |
//! | Low (L) | Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component. |
//! | High (H) | A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected.\[^2\] For example, a successful attack may depend on an attacker overcoming any of the following conditions:<br>*   The attacker must gather knowledge about the environment in which the vulnerable target/component exists. For example, a requirement to collect details on target configuration settings, sequence numbers, or shared secrets.<br>*   The attacker must prepare the target environment to improve exploit reliability. For example, repeated exploitation to win a race condition, or overcoming advanced exploit mitigation techniques.<br>*   The attacker must inject themselves into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g., a man in the middle attack).|
//!
//! _Scoring Guidance_: When deciding between Network and Adjacent, if an attack can be launched over a wide area network or from outside the logically adjacent administrative network domain, use Network. Network should be used even if the attacker is required to be on the same intranet to exploit the vulnerable system (e.g., the attacker can only exploit the vulnerability from inside a corporate network).
//!
use crate::error::{CVSSError, Result};
use crate::metric::Metric;
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
impl Display for AttackComplexityType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::NAME, self.as_str())
  }
}
impl Metric for AttackComplexityType {
  const NAME: &'static str = "AC";

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
    if s.starts_with(Self::NAME) {
      s = s
        .strip_prefix(&format!("{}:", Self::NAME))
        .unwrap_or_default()
        .to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "AttackComplexityType from_str".to_string(),
      })?
    };
    match c {
      'L' => Ok(Self::Low),
      'H' => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "AttackComplexityType".to_string(),
      }),
    }
  }
}
