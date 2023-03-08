use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{convert::TryFrom, fmt, str::FromStr};
use crate::error::CpeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpePart {
    Any,
    Hardware,
    OperatingSystem,
    Application,
}

impl Serialize for CpePart {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(match *self {
            CpePart::Any => "*",
            CpePart::Hardware => "h",
            CpePart::Application => "a",
            CpePart::OperatingSystem => "o",
        })
    }
}

impl<'de> Deserialize<'de> for CpePart {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "h" => CpePart::Hardware,
            "o" => CpePart::OperatingSystem,
            "a" => CpePart::Application,
            _ => CpePart::Any,
        })
    }
}

impl Default for CpePart {
    fn default() -> Self {
        CpePart::Any
    }
}

impl TryFrom<&str> for CpePart {
    type Error = CpeError;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        Self::from_str(val)
    }
}

impl FromStr for CpePart {
    type Err = CpeError;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let c = {
            let c = val.chars().next();
            c.ok_or(CpeError::InvalidPart { value: val.to_string() })?
        };
        match c {
            'h' => Ok(Self::Hardware),
            'o' => Ok(Self::OperatingSystem),
            'a' => Ok(Self::Application),
            _ => Err(CpeError::InvalidPart { value: c.to_string() }),
        }
    }
}

impl fmt::Display for CpePart {
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