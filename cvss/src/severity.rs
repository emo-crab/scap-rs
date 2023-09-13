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
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SeverityTypeV3 {
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

impl Display for SeverityTypeV3 {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "S:{}", self.as_str())
  }
}

impl SeverityTypeV3 {
  fn as_str(&self) -> &'static str {
    match self {
      SeverityTypeV3::None => "None",
      SeverityTypeV3::Low => "Low",
      SeverityTypeV3::Medium => "Medium",
      SeverityTypeV3::High => "High",
      SeverityTypeV3::Critical => "Critical",
    }
  }
}

impl From<f32> for SeverityTypeV3 {
  fn from(value: f32) -> Self {
    if value < 0.1 {
      SeverityTypeV3::None
    } else if value < 4.0 {
      SeverityTypeV3::Low
    } else if value < 7.0 {
      SeverityTypeV3::Medium
    } else if value < 9.0 {
      SeverityTypeV3::High
    } else {
      SeverityTypeV3::Critical
    }
  }
}

impl FromStr for SeverityTypeV3 {
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
      }),
    }
  }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
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
    write!(f, "S:{}", self.as_str())
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
        value: s.to_string(),
      }),
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::severity::SeverityTypeV3;

  #[test]
  fn severity_type_test() {
    assert_eq!(SeverityTypeV3::from(0.0), SeverityTypeV3::None);
    assert_eq!(SeverityTypeV3::from(0.1), SeverityTypeV3::Low);
    assert_eq!(SeverityTypeV3::from(0.3), SeverityTypeV3::Low);
    assert_eq!(SeverityTypeV3::from(1.0), SeverityTypeV3::Low);
    assert_eq!(SeverityTypeV3::from(1.6), SeverityTypeV3::Low);
    assert_eq!(SeverityTypeV3::from(4.0), SeverityTypeV3::Medium);
    assert_eq!(SeverityTypeV3::from(5.0), SeverityTypeV3::Medium);
    assert_eq!(SeverityTypeV3::from(6.0), SeverityTypeV3::Medium);
    assert_eq!(SeverityTypeV3::from(6.9), SeverityTypeV3::Medium);
    assert_eq!(SeverityTypeV3::from(7.0), SeverityTypeV3::High);
    assert_eq!(SeverityTypeV3::from(9.0), SeverityTypeV3::Critical);
    assert_eq!(SeverityTypeV3::from(10.0), SeverityTypeV3::Critical);
  }
}
