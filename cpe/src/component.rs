use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{convert::TryFrom, fmt, str::FromStr};
use crate::error::CpeError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Component {
    Any,
    NA,
    Value(String),
}

impl Serialize for Component {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(match *self {
            Component::Any => "*",
            Component::NA => "-",
            Component::Value(ref other) => other,
        })
    }
}

impl<'de> Deserialize<'de> for Component {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "*" => Component::Any,
            "-" => Component::NA,
            _ => Component::Value(s),
        })
    }
}

impl TryFrom<&str> for Component {
    type Error = CpeError;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        Self::from_str(val)
    }
}

impl TryFrom<String> for Component {
    type Error = CpeError;
    fn try_from(val: String) -> Result<Self, Self::Error> {
        Self::from_str(val.as_str())
    }
}

impl Default for Component {
    fn default() -> Self {
        Component::Any
    }
}

impl FromStr for Component {
    type Err = CpeError;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        Ok(match val {
            "*" => Component::Any,
            "-" => Component::NA,
            _ => Component::Value(val.to_owned()),
        })
    }
}

impl Component {
    pub fn matches(&self, val: &str) -> bool {
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
