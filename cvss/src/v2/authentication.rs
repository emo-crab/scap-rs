use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
// Au
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuthenticationType {
  // Au:M
  Multiple,
  // Au:S
  Single,
  // Au:N
  None,
}
impl FromStr for AuthenticationType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s.to_string(),
        scope: "AuthenticationType from_str".to_string(),
      })?
    };
    match c {
      'M' => Ok(Self::Multiple),
      'S' => Ok(Self::Single),
      'N' => Ok(Self::None),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "AuthenticationType".to_string(),
      }),
    }
  }
}
