//! cvss version
use crate::error::{CVSSError, Result};
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;
use std::str::FromStr;
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub enum Version {
  #[default]
  None,
  #[serde(rename = "2.0")]
  V2_0,
  #[serde(rename = "3.0")]
  V3_0,
  #[serde(rename = "3.1")]
  V3_1,
  #[serde(rename = "4.0")]
  V4_0,
}

impl FromStr for Version {
  type Err = CVSSError;

  fn from_str(s: &str) -> Result<Self> {
    let mut s = s.to_uppercase();
    if s.starts_with("CVSS:") {
      s = s.strip_prefix("CVSS:").unwrap_or_default().to_string();
    }
    match s.as_str() {
      "2.0" => Ok(Self::V2_0),
      "3.0" => Ok(Self::V3_0),
      "3.1" => Ok(Self::V3_1),
      "4.0" => Ok(Self::V4_0),
      _ => Ok(Self::None),
    }
  }
}

impl std::fmt::Display for Version {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      Version::None => write!(f, "NONE"),
      Version::V2_0 => write!(f, "2.0"),
      Version::V3_0 => write!(f, "3.0"),
      Version::V3_1 => write!(f, "3.1"),
      Version::V4_0 => write!(f, "4.0"),
    }
  }
}
