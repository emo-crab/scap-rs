use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

// S
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScopeType {
  // S:U
  Unchanged,
  // S:C
  Changed,
}

impl ScopeType {
  pub fn is_changed(&self) -> bool {
    matches!(self, ScopeType::Changed)
  }

  fn as_str(&self) -> &'static str {
    match self {
      ScopeType::Unchanged => "U",
      ScopeType::Changed => "C",
    }
  }
}
impl Display for ScopeType {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "S:{}", self.as_str())
  }
}
impl FromStr for ScopeType {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with("S:") {
      s = s.strip_prefix("S:").unwrap_or_default().to_string();
    }
    let c = {
      let c = s.to_uppercase().chars().next();
      c.ok_or(CVSSError::InvalidCVSS {
        value: s,
        scope: "ScopeType from_str".to_string(),
      })?
    };
    match c {
      'U' => Ok(Self::Unchanged),
      'C' => Ok(Self::Changed),
      _ => Err(CVSSError::InvalidCVSS {
        value: c.to_string(),
        scope: "ScopeType".to_string(),
      }),
    }
  }
}
