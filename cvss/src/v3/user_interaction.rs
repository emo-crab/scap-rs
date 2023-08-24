//! ### 2.1.4. User Interaction (UI)
//!
//! This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner. The Base Score is greatest when no user interaction is required. The list of possible values is presented in Table 4.
//!
//! **Table 4: User Interaction**
//!
//! | Metric Value | Description |
//! | --- | --- |
//! | None (N) | The vulnerable system can be exploited without interaction from any user. |
//! | Required (R) | Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator. |[](#body)
//!

use crate::error::{CVSSError, Result};
use crate::metric::{Metric, MetricType, MetricTypeV3};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// User Interaction (UI) 用户交互
///
/// 此指标描述攻击脆弱组件对除攻击者之外的用户参与的需求，即确定脆弱组件是仅攻击者本身就可以随意利用，还是需要用户（或用户进程）以某种方式参与。
///
/// > This metric captures the requirement for a user, other than the attacker,
/// > to participate in the successful compromise of the vulnerable component.
/// > This metric determines whether the vulnerability can be exploited solely at the will of the
/// > attacker, or whether a separate user (or user-initiated process) must participate in some manner.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum UserInteractionType {
  /// Require(R) 有需求
  ///
  /// 需要用户采取一些措施才能成功攻击此脆弱组件，例如说服用户单击电子邮件中的链接。
  Required,
  /// None(N) 无需求
  ///
  /// 不需要任何用户的交互就可以成功攻击此脆弱组件。
  None,
}

impl Display for UserInteractionType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl Metric for UserInteractionType {
  const TYPE: MetricType = MetricType::V3(MetricTypeV3::UI);

  fn score(&self) -> f32 {
    match self {
      UserInteractionType::Required => 0.62,
      UserInteractionType::None => 0.85,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      UserInteractionType::Required => "R",
      UserInteractionType::None => "N",
    }
  }
}

impl FromStr for UserInteractionType {
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
      'N' => Ok(Self::None),
      'R' => Ok(Self::Required),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
      }),
    }
  }
}
