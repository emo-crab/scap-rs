use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// CIA 影响指标 原json schema为ciaType
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ImpactMetricsType {
  None,
  Partial,
  Complete,
}
impl FromStr for ImpactMetricsType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s.to_string(),
        scope: "ImpactMetricsType from_str".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::None),
      'A' => Ok(Self::Partial),
      'L' => Ok(Self::Complete),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "ImpactMetricsType".to_string(),
      }),
    }
  }
}
