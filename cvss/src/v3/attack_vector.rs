use crate::error::{CVSSError, Result};
use crate::metric::Metric;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

// AV
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackVectorType {
  // AV:N
  Network,
  // AV:A
  AdjacentNetwork,
  // AV:L
  Local,
  // AV:P
  Physical,
}

impl Display for AttackVectorType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}", Self::NAME, self.as_str())
  }
}

impl Metric for AttackVectorType {
  const NAME: &'static str = "AV";

  fn score(&self) -> f32 {
    match self {
      AttackVectorType::Network => 0.85,
      AttackVectorType::AdjacentNetwork => 0.62,
      AttackVectorType::Local => 0.55,
      AttackVectorType::Physical => 0.2,
    }
  }

  fn as_str(&self) -> &'static str {
    match self {
      AttackVectorType::Physical => "P",
      AttackVectorType::Local => "L",
      AttackVectorType::AdjacentNetwork => "A",
      AttackVectorType::Network => "N",
    }
  }
}
impl FromStr for AttackVectorType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with("AV:") {
      s = s.strip_prefix("AV:").unwrap_or_default().to_string();
    }
    let c = {
      let c = s.chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "AttackVectorType from_str".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::Network),
      'A' => Ok(Self::AdjacentNetwork),
      'L' => Ok(Self::Local),
      'P' => Ok(Self::Physical),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "AttackVectorType".to_string(),
      }),
    }
  }
}
