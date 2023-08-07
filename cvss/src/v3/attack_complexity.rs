use crate::error::{CVSSError, Result};
use crate::metric::Metric;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

// AC
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackComplexityType {
  // AC:H
  High,
  // AC:L
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
      AttackComplexityType::High => 0.72,
      AttackComplexityType::Low => 0.44,
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
    if s.starts_with("AC:") {
      s = s.strip_prefix("AC:").unwrap_or_default().to_string();
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
