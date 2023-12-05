//! component
use language_tags::LanguageTag;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{convert::TryFrom, fmt, str::FromStr};

use crate::error::{CPEError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Language {
  // 任意值
  #[default]
  Any,
  //不适用
  NA,
  // 解析错误
  Value(String),
  // 符合语言
  Language(LanguageTag),
}

impl FromStr for Language {
  type Err = CPEError;
  fn from_str(s: &str) -> Result<Self> {
    match LanguageTag::parse(s) {
      Err(_) => match s {
        "*" => Ok(Self::Any),
        "-" => Ok(Self::NA),
        _ => Ok(Self::Value(s.to_string())),
      },
      Ok(tag) => Ok(Self::Language(tag)),
    }
  }
}

impl TryFrom<&str> for Language {
  type Error = CPEError;
  fn try_from(val: &str) -> Result<Self> {
    Self::from_str(val)
  }
}

impl TryFrom<String> for Language {
  type Error = CPEError;
  fn try_from(val: String) -> Result<Self> {
    Self::from_str(val.as_str())
  }
}

impl fmt::Display for Language {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "{}",
      match self {
        Language::Any => "*",
        Language::NA => "-",
        Language::Value(s) => s.as_str(),
        Language::Language(v) => v.as_str(),
      }
    )
  }
}

impl Serialize for Language {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(match self {
      Language::Any => "*",
      Language::NA => "-",
      Language::Value(s) => s.as_str(),
      Language::Language(ref other) => other.as_str(),
    })
  }
}

impl<'de> Deserialize<'de> for Language {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    Ok(match LanguageTag::parse(&s) {
      Err(_) => match s.as_str() {
        "*" => Language::Any,
        "-" => Language::NA,
        _ => Language::Value(s.to_string()),
      },
      Ok(tag) => Language::Language(tag),
    })
  }
}
// 组件
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Component {
  // 任意值
  #[default]
  Any,
  // 不适用
  NA,
  //组件名
  Value(String),
}

impl Serialize for Component {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(match *self {
      Component::Any => "*",
      Component::NA => "-",
      Component::Value(ref other) => other,
    })
  }
}

impl<'de> Deserialize<'de> for Component {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: Deserializer<'de>,
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
  type Error = CPEError;
  fn try_from(val: &str) -> Result<Self> {
    Self::from_str(val)
  }
}

impl TryFrom<String> for Component {
  type Error = CPEError;
  fn try_from(val: String) -> Result<Self> {
    Self::from_str(val.as_str())
  }
}

impl FromStr for Component {
  type Err = CPEError;

  fn from_str(val: &str) -> Result<Self> {
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
