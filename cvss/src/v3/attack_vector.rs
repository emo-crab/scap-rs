use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
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

impl From<AttackVectorType> for f32 {
  fn from(val: AttackVectorType) -> Self {
    match val {
      AttackVectorType::Network => 0.85,
      AttackVectorType::AdjacentNetwork => 0.62,
      AttackVectorType::Local => 0.55,
      AttackVectorType::Physical => 0.2,
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
        value: s.to_string(),
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
