//! ### Privileges Required (PR)
//!
//! This metric describes the level of privileges an attacker must possess _prior to_ successfully exploiting the vulnerability. The method by which the attacker obtains privileged credentials prior to the attack (e.g., free trial accounts), is outside the scope of this metric. Generally, self-service provisioned accounts do not constitute a privilege requirement if the attacker can grant themselves privileges as part of the attack.
//!
//! The resulting score is greatest if no privileges are required. The list of possible values is presented in Table 4.
//!
//! **Table 4: Privileges Required**
//!
//! | **Metric Value** | **Description** |
//! | --- | --- |
//! | None (N) | The attacker is unauthenticated prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack. |
//! | Low (L) | The attacker requires privileges that provide basic capabilities that are typically limited to settings and resources owned by a single low-privileged user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources. |
//! | High (H) | The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable system allowing full access to the vulnerable system’s settings and files. |
//!
//! **Assessment Guidance:** Privileges Required is usually None for hard-coded credential vulnerabilities or vulnerabilities requiring social engineering (e.g., reflected cross-site scripting, cross-site request forgery, or file parsing vulnerability in a PDF reader). Default credentials that have not been changed or are not unique across each environment should be treated similarly to hard-coded credentials.
//!

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV3, Worth};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Privilege Required (PR) 权限要求
///
/// 此指标描述攻击者在成功攻击脆弱组件之前必须拥有的权限级别。
///
/// This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegesRequiredType {
  /// High(H) 高权要求
  ///
  /// 攻击者需要对可能影响组件范围设置和文件的易受攻击组件提供重要（如管理）控制的权限。
  High,
  /// Low(L) 低权要求
  ///
  /// 攻击者需要拥有基本用户功能的特权，通常只影响普通用户拥有的设置和文件。或者，具有低权限的攻击者可能只能对非敏感资源造成影响。
  Low,
  /// None(N) 无要求
  ///
  /// 攻击者在攻击之前无需经过授权，因此不需要访问设置或文件来执行攻击。
  None,
}

impl Display for PrivilegesRequiredType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl PrivilegesRequiredType {
  #[allow(dead_code)]
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}

impl PrivilegesRequiredType {
  pub(crate) fn is_none(&self) -> bool {
    matches!(self, Self::None)
  }
}
impl Metric for PrivilegesRequiredType {
  const TYPE: MetricType = MetricType::V3(MetricTypeV3::PR);

  fn help(&self) -> Help {
    match self {
      PrivilegesRequiredType::High => {Help{ worth: Worth::Bad, des: "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable system allowing full access to the vulnerable system’s settings and files.".to_string() }}
      PrivilegesRequiredType::Low => {Help{ worth: Worth::Worse, des: "The attacker requires privileges that provide basic capabilities that are typically limited to settings and resources owned by a single low-privileged user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.".to_string() }}
      PrivilegesRequiredType::None => {Help{ worth: Worth::Worst, des: "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      PrivilegesRequiredType::High => 0.2,
      PrivilegesRequiredType::Low => 0.1,
      PrivilegesRequiredType::None => 0.0,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      PrivilegesRequiredType::High => "H",
      PrivilegesRequiredType::Low => "L",
      PrivilegesRequiredType::None => "N",
    }
  }
}
impl FromStr for PrivilegesRequiredType {
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
      Some('L') => Ok(Self::Low),
      Some('H') => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "N,L,H".to_string(),
      }),
    }
  }
}
