use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// AC
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AccessComplexityType {
  // AC:H
  High,
  // AC:M
  Medium,
  // AC:L
  Low,
}
impl FromStr for AccessComplexityType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s.to_string(),
        scope: "AccessComplexityType from_str".to_string(),
      })?
    };
    match c {
      'H' => Ok(Self::High),
      'M' => Ok(Self::Medium),
      'L' => Ok(Self::Low),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "AccessComplexityType".to_string(),
      }),
    }
  }
}
