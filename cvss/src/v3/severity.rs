use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// 严重性
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SeverityType {
  // 未校正
  None,
  // 低危
  Low,
  // 中危
  Medium,
  // 高危
  High,
  // 严重
  Critical,
}


impl FromStr for SeverityType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s.to_string(),
        scope: "SeverityType from_str".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::None),
      'L' => Ok(Self::Low),
      'M' => Ok(Self::Medium),
      'H' => Ok(Self::High),
      'C' => Ok(Self::Critical),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "SeverityType".to_string(),
      }),
    }
  }
}
