use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{de, Deserialize, Deserializer};
use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;

pub mod date_format {
  use chrono::{NaiveDate, NaiveDateTime, Utc};
  use serde::{self, Deserialize, Deserializer, Serializer};

  pub(crate) const FORMAT: &str = "%Y-%m-%d";

  pub fn serialize<S>(date: &NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let s = date.to_string();
    serializer.serialize_str(&s)
  }

  pub fn deserialize<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
      return Ok(Utc::now().naive_local());
    }
    match NaiveDate::parse_from_str(&s, FORMAT) {
      Ok(naive_datetime) => Ok(
        naive_datetime
          .and_hms_opt(0, 0, 0)
          .unwrap_or(Utc::now().naive_local()),
      ),
      Err(err) => Err(serde::de::Error::custom(err)),
    }
  }
}
/// 字符串转set
pub fn string_to_hashset<'de, D>(deserializer: D) -> Result<HashSet<String>, D::Error>
where
  D: Deserializer<'de>,
{
  struct StringToHashSet(PhantomData<HashSet<String>>);
  impl<'de> de::Visitor<'de> for StringToHashSet {
    type Value = HashSet<String>;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
      formatter.write_str("string or list of strings")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
      E: de::Error,
    {
      let name: Vec<String> = value
        .split(',')
        .filter(|s| !s.starts_with("cve"))
        .map(String::from)
        .collect();
      Ok(HashSet::from_iter(name))
    }
    fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
    where
      S: de::SeqAccess<'de>,
    {
      Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
    }
  }
  deserializer.deserialize_any(StringToHashSet(PhantomData))
}
pub fn rfc3339_deserialize<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
  D: Deserializer<'de>,
{
  let s = String::deserialize(deserializer)?;
  if s.is_empty() {
    return Ok(Utc::now().naive_local());
  }
  match DateTime::parse_from_rfc2822(&s) {
    Ok(naive_datetime) => Ok(naive_datetime.naive_local()),
    Err(err) => Err(serde::de::Error::custom(err)),
  }
}
