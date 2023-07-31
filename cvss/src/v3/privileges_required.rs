use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
// PR
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegesRequiredType {
  // PR:H
  High,
  // PR:L
  Low,
  // PR:N
  None,
}

// impl Into<f32> for PrivilegesRequiredType {
//   fn into(self) -> f32 {
//     match self {
//       PrivilegesRequiredType::High => {}
//       PrivilegesRequiredType::Low => {}
//       PrivilegesRequiredType::None => {}
//     }
//   }
// }
impl FromStr for PrivilegesRequiredType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with("PR:") {
      s = s.strip_prefix("PR:").unwrap_or_default().to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "PrivilegesRequiredType from_str".to_string(),
      })?
    };
    match c {
      'N' => Ok(Self::None),
      'L' => Ok(Self::Low),
      'H' => Ok(Self::High),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "PrivilegesRequiredType".to_string(),
      }),
    }
  }
}
