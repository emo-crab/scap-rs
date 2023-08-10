//! part
use crate::error::{CPEError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CPEPart {
  // any
  Any,
  // 硬件设备 h
  Hardware,
  // 操作系统 o
  OperatingSystem,
  // 应用程序 a
  Application,
}

impl Serialize for CPEPart {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(match *self {
      CPEPart::Any => "*",
      CPEPart::Hardware => "h",
      CPEPart::Application => "a",
      CPEPart::OperatingSystem => "o",
    })
  }
}

impl<'de> Deserialize<'de> for CPEPart {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    Ok(match s.as_str() {
      "h" => CPEPart::Hardware,
      "o" => CPEPart::OperatingSystem,
      "a" => CPEPart::Application,
      _ => CPEPart::Any,
    })
  }
}

impl Default for CPEPart {
  fn default() -> Self {
    CPEPart::Any
  }
}

impl FromStr for CPEPart {
  type Err = CPEError;

  fn from_str(val: &str) -> Result<Self> {
    let c = {
      let c = val.chars().next();
      c.ok_or(CPEError::InvalidPart {
        value: val.to_string(),
      })?
    };
    match c {
      'h' => Ok(Self::Hardware),
      'o' => Ok(Self::OperatingSystem),
      'a' => Ok(Self::Application),
      _ => Err(CPEError::InvalidPart {
        value: c.to_string(),
      }),
    }
  }
}

impl fmt::Display for CPEPart {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::Hardware => write!(f, "h"),
      Self::OperatingSystem => write!(f, "o"),
      Self::Application => write!(f, "a"),
      Self::Any => {
        if f.alternate() {
          write!(f, "*")
        } else {
          write!(f, "ANY")
        }
      }
    }
  }
}
