//! part
use crate::error::{CPEError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Part {
  // any
  #[default]
  Any,
  // 硬件设备 h
  Hardware,
  // 操作系统 o
  OperatingSystem,
  // 应用程序 a
  Application,
}

impl Serialize for Part {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(match *self {
      Part::Any => "*",
      Part::Hardware => "h",
      Part::Application => "a",
      Part::OperatingSystem => "o",
    })
  }
}

impl<'de> Deserialize<'de> for Part {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    Ok(match s.as_str() {
      "h" => Part::Hardware,
      "o" => Part::OperatingSystem,
      "a" => Part::Application,
      _ => Part::Any,
    })
  }
}

impl From<Part> for char {
  fn from(val: Part) -> Self {
    match val {
      Part::Any => '*',
      Part::Hardware => 'h',
      Part::OperatingSystem => 'o',
      Part::Application => 'a',
    }
  }
}
impl FromStr for Part {
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

impl fmt::Display for Part {
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
