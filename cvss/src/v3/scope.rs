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
use crate::metric::Metric;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

// S
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScopeType {
  // S:U
  Unchanged,
  // S:C
  Changed,
}

impl ScopeType {
  pub fn is_changed(&self) -> bool {
    matches!(self, ScopeType::Changed)
  }

  fn as_str(&self) -> &'static str {
    match self {
      ScopeType::Unchanged => "U",
      ScopeType::Changed => "C",
    }
  }
}
impl Display for ScopeType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::NAME, self.as_str())
  }
}

impl Metric for ScopeType {
  const NAME: &'static str = "S";

  fn score(&self) -> f32 {
    match self {
      ScopeType::Unchanged => 6.42,
      ScopeType::Changed => 7.52,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      ScopeType::Unchanged => "U",
      ScopeType::Changed => "C",
    }
  }
}
impl FromStr for ScopeType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with("S:") {
      s = s.strip_prefix("S:").unwrap_or_default().to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "ScopeType from_str".to_string(),
      })?
    };
    match c {
      'U' => Ok(Self::Unchanged),
      'C' => Ok(Self::Changed),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "ScopeType".to_string(),
      }),
    }
  }
}
