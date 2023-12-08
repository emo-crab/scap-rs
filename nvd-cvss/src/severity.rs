//! 5\. Qualitative Severity Rating Scale
//!
//! For some purposes it is useful to have a textual representation of the numeric Base, Temporal and Environmental scores. All scores can be mapped to the qualitative ratings defined in Table 14.\[^3\]
//!
//! **Table 14: Qualitative severity rating scale**
//!
//! | Rating | CVSS Score |
//! | --- | --- |
//! | None | 0.0 |
//! | Low | 0.1 - 3.9 |
//! | Medium | 4.0 - 6.9 |
//! | High | 7.0 - 8.9 |
//! | Critical | 9.0 - 10.0 |
//!
//! As an example, a CVSS Base Score of 4.0 has an associated severity rating of Medium. The use of these qualitative severity ratings is optional, and there is no requirement to include them when publishing CVSS scores. They are intended to help organizations properly assess and prioritize their vulnerability management processes.
//!
use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// 定性严重程度
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum SeverityType {
  /// 未校正 | None | 0.0 |
  None,
  /// 低危 | Low | 0.1 - 3.9 |
  Low,
  /// 中危 | Medium | 4.0 - 6.9 |
  Medium,
  /// 高危 | High | 7.0 - 8.9 |
  High,
  /// 严重 | Critical | 9.0 - 10.0 |
  Critical,
}

impl Display for SeverityType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.as_str())
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
        key: "SeverityType".to_string(),
        value: s.to_string(),
        expected: "None,Low,Medium,High,Critical".to_string(),
      }),
    }
  }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum SeverityTypeV2 {
  /// 未校正 | None | 0.0 |
  None,
  /// 低危 | Low | 0.0 - 3.9 |
  Low,
  /// 中危 | Medium | 4.0 - 6.9 |
  Medium,
  /// 高危 | High | 7.0 - 10.0 |
  High,
}

impl Display for SeverityTypeV2 {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.as_str())
  }
}

impl SeverityTypeV2 {
  fn as_str(&self) -> &'static str {
    match self {
      SeverityTypeV2::None => "None",
      SeverityTypeV2::Low => "Low",
      SeverityTypeV2::Medium => "Medium",
      SeverityTypeV2::High => "High",
    }
  }
}

impl From<f32> for SeverityTypeV2 {
  fn from(value: f32) -> Self {
    if value < 0.1 {
      SeverityTypeV2::None
    } else if value < 4.0 {
      SeverityTypeV2::Low
    } else if value < 7.0 {
      SeverityTypeV2::Medium
    } else {
      SeverityTypeV2::High
    }
  }
}

impl FromStr for SeverityTypeV2 {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    match s {
      "None" => Ok(Self::None),
      "Low" => Ok(Self::Low),
      "Medium" => Ok(Self::Medium),
      "High" => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        key: "SeverityTypeV2".to_string(),
        value: s.to_string(),
        expected: "None,Low,Medium,High".to_string(),
      }),
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::severity::SeverityType;

  #[test]
  fn severity_type_test() {
    assert_eq!(SeverityType::from(0.0), SeverityType::None);
    assert_eq!(SeverityType::from(0.1), SeverityType::Low);
    assert_eq!(SeverityType::from(0.3), SeverityType::Low);
    assert_eq!(SeverityType::from(1.0), SeverityType::Low);
    assert_eq!(SeverityType::from(1.6), SeverityType::Low);
    assert_eq!(SeverityType::from(4.0), SeverityType::Medium);
    assert_eq!(SeverityType::from(5.0), SeverityType::Medium);
    assert_eq!(SeverityType::from(6.0), SeverityType::Medium);
    assert_eq!(SeverityType::from(6.9), SeverityType::Medium);
    assert_eq!(SeverityType::from(7.0), SeverityType::High);
    assert_eq!(SeverityType::from(9.0), SeverityType::Critical);
    assert_eq!(SeverityType::from(10.0), SeverityType::Critical);
  }
}
