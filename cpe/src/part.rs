use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};
use crate::error::CpeError;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum CpePart {
    Any,
    Hardware,
    OperatingSystem,
    Application,
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
            _ => Err(CpeError::InvalidCpeType { value: c.to_string() }),
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