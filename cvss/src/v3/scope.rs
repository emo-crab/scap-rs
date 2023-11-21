//! 2.2. Scope (S)
//!
//! The Scope metric captures whether a vulnerability in one vulnerable component impacts resources in components beyond its _security scope_.
//!
//! Formally, a _security authority_ is a mechanism (e.g., an application, an operating system, firmware, a sandbox environment) that defines and enforces access control in terms of how certain subjects/actors (e.g., human users, processes) can access certain restricted objects/resources (e.g., files, CPU, memory) in a controlled manner. All the subjects and objects under the jurisdiction of a single _security authority_ are considered to be under one _security scope_. If a vulnerability in a vulnerable component can affect a component which is in a different _security scope_ than the vulnerable component, a Scope change occurs. Intuitively, whenever the impact of a vulnerability breaches a security/trust boundary and impacts components outside the security scope in which vulnerable component resides, a Scope change occurs.
//!
//! The security scope of a component encompasses other components that provide functionality solely to that component, even if these other components have their own security authority. For example, a database used solely by one application is considered part of that application’s security scope even if the database has its own security authority, e.g., a mechanism controlling access to database records based on database users and associated database privileges.
//!
//! The Base Score is greatest when a scope change occurs. The list of possible values is presented in Table 5.
//!
//! **Table 5: Scope**
//!
//! | Metric Value | Description |
//! | --- | --- |
//! | Unchanged (U) | An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority. |
//! | Changed (C) | An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities. |[](#body)
//!

use crate::error::{CVSSError, Result};
use crate::metric::{Help, Metric, MetricType, MetricTypeV3, Worth};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Scope 影响范围
///
/// CVSS3.0版计算的一个重要属性，反映软件组件中的漏洞会否影响其以外的资源或获得其以外的权限。这一结果由度量值 授权域 或 简单域表示。
///
/// An important property captured by CVSS v3.0 is the ability for a vulnerability in one software component to impact resources beyond its means, or privileges. This consequence is represented by the metric Authorization Scope, or simply Scope.
///
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScopeType {
  /// unchanged(U) 固定
  ///
  /// 被利用的漏洞只能影响由同一当局管理的资源。在这种情况下，脆弱组件 和 受影响组件是同一个。
  Unchanged,
  /// changed(C) 变化
  ///
  /// 被利用的漏洞可能会影响超出脆弱组件预期授权权限的资源。在这种情况下，脆弱组件和受影响组件并非同一个。
  Changed,
}

impl ScopeType {
  pub fn is_changed(&self) -> bool {
    matches!(self, ScopeType::Changed)
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::Unchanged => "U",
      Self::Changed => "C",
    }
  }
}
impl Display for ScopeType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::name(), self.as_str())
  }
}

impl ScopeType {
  pub fn metric_help(&self) -> Help {
    self.help()
  }
}
impl Metric for ScopeType {
  const TYPE: MetricType = MetricType::V3(MetricTypeV3::S);

  fn help(&self) -> Help {
    match self {
      Self::Unchanged => {Help{ worth: Worth::Bad, des: "An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.".to_string() }}
      Self::Changed => {Help{ worth: Worth::Worst, des: "An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.".to_string() }}
    }
  }

  fn score(&self) -> f32 {
    match self {
      Self::Unchanged => 6.42,
      Self::Changed => 7.52,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      Self::Unchanged => "U",
      Self::Changed => "C",
    }
  }
}
impl FromStr for ScopeType {
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
      Some('U') => Ok(Self::Unchanged),
      Some('C') => Ok(Self::Changed),
      _ => Err(CVSSError::InvalidCVSS {
        key: name.to_string(),
        value: format!("{:?}", c),
        expected: "U,C".to_string(),
      }),
    }
  }
}
