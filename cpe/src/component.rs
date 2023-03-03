use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Component {
    Any,
    NA,
    Value(String),
}

impl TryFrom<&str> for Component {
    type Error = String;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        Self::from_str(val)
    }
}

impl Default for Component {
    fn default() -> Self {
        Component::Any
    }
}

impl FromStr for Component {
    type Err = String;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        Ok(match val {
            "*" => Component::Any,
            "-" => Component::NA,
            _ => Component::Value(val.to_owned()),
        })
    }
}

impl Component {
    #[allow(dead_code)]
    fn matches(&self, val: &str) -> bool {
        match self {
            Component::Any => true,
            Component::NA => false,
            Component::Value(v) => v == val,
        }
    }

    pub fn is_any(&self) -> bool {
        matches!(self, Component::Any)
    }

    pub fn is_na(&self) -> bool {
        matches!(self, Component::NA)
    }

    pub fn is_value(&self) -> bool {
        matches!(self, Component::Value(_))
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Component::Any => "*".to_owned(),
                Component::NA => "-".to_owned(),
                Component::Value(v) => v.to_owned(),
            }
        )
    }
}
