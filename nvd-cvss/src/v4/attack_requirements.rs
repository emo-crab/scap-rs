//! ### Attack Requirements (AT)
//!
//! This metric captures the prerequisite **deployment and execution conditions or variables** of the vulnerable system that enable the attack. These differ from security-enhancing techniques/technologies (ref _Attack Complexity_) as the primary purpose of these conditions is **not** to explicitly mitigate attacks, but rather, emerge naturally as a consequence of the deployment and execution of the vulnerable system. If the attacker does not take action to overcome these conditions, the attack may succeed only occasionally or not succeed at all.
//!
//! **Table 3: Attack Requirements**
//!
//! | **Metric Value** | **Description** |
//! | --- | --- |
//! | None (N) | The successful attack does not depend on the deployment and execution conditions of the vulnerable system. The attacker can expect to be able to reach the vulnerability and execute the knowledge_base under all or most instances of the vulnerability. |
//! | Present (P) | The successful attack depends on the presence of specific deployment and execution conditions of the vulnerable system that enable the attack. These include: A **race condition** must be won to successfully knowledge_base the vulnerability. The successfulness of the attack is conditioned on execution conditions that are not under full control of the attacker. The attack may need to be launched multiple times against a single target before being successful. Network injection. The attacker must inject themselves into the logical network path between the target and the resource requested by the victim (e.g. vulnerabilities requiring an on-path attacker). |
//!

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV4, Worth};

/// Attack Complexity (AC) 攻击复杂度
///
/// 攻击复杂度为攻击者无法控制的条件，这些条件必须存在才能攻击脆弱组件。
/// 如下文所述，这些条件可能需要预先收集有关目标或系统的配置或计算异常等更多信息。
///
/// > The Attack Complexity metric describes the conditions beyond the attacker's control that must
/// > exist in order to knowledge_base the vulnerability. As described below, such conditions may require
/// > the collection of more information about the target, the presence of certain system
/// > configuration settings, or computational exceptions.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackRequirementsType {
  /// High(H) 高复杂度
  ///
  /// 攻击无法随意完成，攻击者在攻击成功之前，需要对脆弱组件投入大量的准备。
  Present,
  /// Low(L) 低复杂度
  ///
  /// 攻击者可以随意攻击，不存在惩罚机制。
  None,
}

impl AttackRequirementsType {
  #[allow(dead_code)]
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}

impl AttackRequirementsType {
  pub(crate) fn is_none(&self) -> bool {
    matches!(self, Self::None)
  }
}
impl Display for AttackRequirementsType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}
impl Metric for AttackRequirementsType {
  const TYPE: MetricType = MetricType::V4(MetricTypeV4::AT);

  fn help(&self) -> Help {
    match self {
      AttackRequirementsType::Present => { Help { worth: Worth::Bad, des: "The successful attack depends on the presence of specific deployment and execution conditions of the vulnerable system that enable the attack. These include: a race condition must be won to successfully knowledge_base the vulnerability (the successfulness of the attack is conditioned on execution conditions that are not under full control of the attacker, or the attack may need to be launched multiple times against a single target before being successful); the attacker must inject themselves into the logical network path between the target and the resource requested by the victim (e.g. vulnerabilities requiring an on-path attacker).".to_string() } }
      AttackRequirementsType::None => { Help { worth: Worth::Worst, des: "The attacker must take no measurable action to knowledge_base the vulnerability. The attack requires no target-specific circumvention to knowledge_base the vulnerability. An attacker can expect repeatable success against the vulnerable system.".to_string() } }
    }
  }

  fn score(&self) -> f32 {
    match self {
      AttackRequirementsType::Present => 0.1,
      AttackRequirementsType::None => 0.0,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      AttackRequirementsType::Present => "P",
      AttackRequirementsType::None => "N",
    }
  }
}
impl FromStr for AttackRequirementsType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let name = Self::name();
    let s = s.to_uppercase();
    let (_name, v) = s
      .split_once(&format!("{}:", name))
      .ok_or(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: s.to_string(),
        expected: name.to_string(),
      })?;
    let c = v.chars().next();
    match c {
      Some('N') => Ok(Self::None),
      Some('P') => Ok(Self::Present),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "N,P".to_string(),
      }),
    }
  }
}
