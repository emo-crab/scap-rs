use crate::error::{CVSSError, Result};
use crate::metric::Metric;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

// PR
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegesRequiredType {
  // PR:H
  High,
  // PR:L
  Low,
  // PR:N
  None,
}

impl Display for PrivilegesRequiredType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::NAME, self.as_str())
  }
}

impl Metric for PrivilegesRequiredType {
  const NAME: &'static str = "PR";

  fn score(&self) -> f32 {
    self.scoped_score(false)
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
    let mut s = s.to_uppercase();
    if s.starts_with("PR:") {
      s = s.strip_prefix("PR:").unwrap_or_default().to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "PrivilegesRequiredType from_str".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::None),
      'L' => Ok(Self::Low),
      'H' => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "PrivilegesRequiredType".to_string(),
      }),
    }
  }
}

impl PrivilegesRequiredType {
  fn scoped_score(&self, scope_change: bool) -> f32 {
    match self {
      PrivilegesRequiredType::High => {
        if scope_change {
          0.50
        } else {
          0.27
        }
      }
      PrivilegesRequiredType::Low => {
        if scope_change {
          0.68
        } else {
          0.62
        }
      }
      PrivilegesRequiredType::None => 0.85,
    }
  }
}
