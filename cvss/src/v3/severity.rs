use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
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

impl Display for SeverityType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "S:{}", self.as_str())
  }
}

impl SeverityType {
  fn as_str(&self) -> &'static str {
    match self {
      SeverityType::None => "None",
      SeverityType::Low => "Low",
      SeverityType::Medium => "Medium",
      SeverityType::High => "High",
      SeverityType::Critical => "Critical",
    }
  }
}

impl From<f32> for SeverityType {
  fn from(value: f32) -> Self {
    if value < 0.1 {
      SeverityType::None
    } else if value < 4.0 {
      SeverityType::Low
    } else if value < 7.0 {
      SeverityType::Medium
    } else if value < 9.0 {
      SeverityType::High
    } else {
      SeverityType::Critical
    }
  }
}

impl FromStr for SeverityType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    match s {
      "None" => Ok(Self::None),
      "Low" => Ok(Self::Low),
      "Medium" => Ok(Self::Medium),
      "High" => Ok(Self::High),
      "Critical" => Ok(Self::Critical),
      _ => Err(CVSSError::InvalidCVSS {
        value: s.to_string(),
        scope: "SeverityType".to_string(),
      }),
    }
  }
}
