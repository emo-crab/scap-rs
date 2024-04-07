use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::io;
use std::str::FromStr;

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OrderMap {
  pub name: String,
  pub order: OrderBy,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum OrderBy {
  #[default]
  Asc,
  Desc,
}

impl Display for OrderBy {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      OrderBy::Asc => f.write_str(""),
      OrderBy::Desc => f.write_str("-"),
    }
  }
}

impl Display for OrderMap {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    f.write_str(&format!("{}{}", self.order, self.name))
  }
}

impl FromStr for OrderMap {
  type Err = io::Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let order = if s.starts_with('-') {
      OrderBy::Desc
    } else {
      OrderBy::Asc
    };
    Ok(OrderMap {
      name: s.strip_prefix('-').unwrap_or_default().to_string(),
      order,
    })
  }
}

pub mod order_serde {
  use crate::common::order::OrderMap;
  use serde::{Deserialize, Deserializer, Serializer};
  use std::str::FromStr;

  pub fn serialize<S: Serializer>(v: &Option<OrderMap>, s: S) -> Result<S::Ok, S::Error> {
    match v {
      None => s.serialize_none(),
      Some(v) => serde::Serialize::serialize(&v.to_string(), s),
    }
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<OrderMap>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
      None => Ok(None),
      Some(s) => match crate::common::order::OrderMap::from_str(&s) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(serde::de::Error::custom(e)),
      },
    }
  }
}
