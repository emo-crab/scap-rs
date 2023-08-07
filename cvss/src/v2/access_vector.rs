use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
// AV
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessVectorType {
  // AV:N
  Network,
  // AV:A
  AdjacentNetwork,
  // AV:L
  Local,
}
impl FromStr for AccessVectorType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s.to_string(),
        scope: "AccessVectorType from_str".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::Network),
      'A' => Ok(Self::AdjacentNetwork),
      'L' => Ok(Self::Local),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "AccessVectorType".to_string(),
      }),
    }
  }
}
