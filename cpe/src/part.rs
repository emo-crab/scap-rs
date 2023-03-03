use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum CpePart {
    Hardware,
    OperatingSystem,
    Application,
}

impl TryFrom<&str> for CpePart {
    type Error = String;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        Self::from_str(val)
    }
}

impl FromStr for CpePart {
    type Err = String;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let c = {
            let c = val.chars().next();
            c.ok_or("No chars for type")?
        };
        match c {
            'h' => Ok(Self::Hardware),
            'o' => Ok(Self::OperatingSystem),
            'a' => Ok(Self::Application),
            _ => Err(format!("could not convert '{}' to cpe type", c)),
        }
    }
}

impl fmt::Display for CpePart {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Hardware => write!(f, "h"),
            Self::OperatingSystem => write!(f, "o"),
            Self::Application => write!(f, "a"),
        }
    }
}