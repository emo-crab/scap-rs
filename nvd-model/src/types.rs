#[cfg(feature = "db")]
use crate::DB;
#[cfg(feature = "db")]
use diesel::deserialize::FromSql;
#[cfg(feature = "db")]
use diesel::serialize::{Output, ToSql};
#[cfg(feature = "db")]
use diesel::{backend::Backend, deserialize, serialize, sql_types::Json, AsExpression, FromSqlRow};
#[cfg(feature = "db")]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Deref, DerefMut};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(AsExpression, FromSqlRow), diesel(sql_type = Json))]
#[serde(transparent)]
pub struct AnyValue<T: Clone>
where
  T: Clone,
{
  inner: T,
}

impl<T: Debug + Clone> Display for AnyValue<T> {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    f.write_fmt(format_args!("{:?}", self.inner))
  }
}

impl<T: Debug + Clone> Debug for AnyValue<T> {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    f.write_fmt(format_args!("{:?}", self.inner))
  }
}

impl<T: Default + for<'de> serde::Deserialize<'de> + Clone> AnyValue<T> {
  pub fn new(t: T) -> Self {
    Self { inner: t }
  }
}

impl<T: Default + Clone> Deref for AnyValue<T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

impl<T: Default + Clone> DerefMut for AnyValue<T> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.inner
  }
}

impl<T: Default + Clone> Default for AnyValue<T> {
  fn default() -> Self {
    Self {
      inner: T::default(),
    }
  }
}

#[cfg(feature = "db")]
impl<T: Debug + Clone, DB: Backend> FromSql<Json, DB> for AnyValue<T>
where
  serde_json::Value: FromSql<Json, DB>,
  T: DeserializeOwned,
{
  fn from_sql(bytes: DB::RawValue<'_>) -> deserialize::Result<Self> {
    let value = <serde_json::Value as FromSql<Json, DB>>::from_sql(bytes)?;
    Ok(serde_json::from_value(value)?)
  }
}

#[cfg(feature = "db")]
impl<T: Debug + Clone> ToSql<Json, DB> for AnyValue<T>
where
  serde_json::Value: ToSql<Json, DB>,
  T: Serialize,
{
  fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> serialize::Result {
    let value = serde_json::to_value(&self.inner)?;
    <serde_json::Value as ToSql<Json, DB>>::to_sql(&value, &mut out.reborrow())
  }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum MetaData {
  HashMap(HashMap<String, HashMap<String, String>>),
  HashSet(HashMap<String, HashSet<String>>),
}

impl Debug for MetaData {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      MetaData::HashMap(m) => f.write_fmt(format_args!("{:?}", m)),
      MetaData::HashSet(s) => f.write_fmt(format_args!("{:?}", s)),
    }
  }
}

impl Display for MetaData {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      MetaData::HashMap(m) => f.write_fmt(format_args!("{:?}", m)),
      MetaData::HashSet(s) => f.write_fmt(format_args!("{:?}", s)),
    }
  }
}

impl Default for MetaData {
  fn default() -> Self {
    MetaData::HashSet(HashMap::default())
  }
}

impl MetaData {
  pub fn from_hashmap(name: impl Into<String>, hm: HashMap<String, String>) -> MetaData {
    let mut i: HashMap<String, HashMap<String, String>> = HashMap::new();
    i.insert(name.into(), hm);
    MetaData::HashMap(i)
  }
  pub fn from_hashset(name: impl Into<String>, hm: impl Into<HashSet<String>>) -> MetaData {
    let mut i: HashMap<String, HashSet<String>> = HashMap::new();
    i.insert(name.into(), hm.into());
    MetaData::HashSet(i)
  }
  pub fn get_hashmap(&self, key: &str) -> Option<&HashMap<String, String>> {
    match self {
      MetaData::HashMap(m) => {
        return m.get(key);
      }
      MetaData::HashSet(_) => None,
    }
  }
  pub fn get_hashset(&self, key: &str) -> Option<&HashSet<String>> {
    match self {
      MetaData::HashMap(_) => None,
      MetaData::HashSet(s) => s.get(key),
    }
  }
}

pub mod uuid_serde {
  use serde::{Deserializer, Serializer};

  pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    match uuid::Uuid::from_slice(v) {
      Ok(u) => uuid::serde::compact::serialize(&u, s),
      Err(e) => Err(serde::ser::Error::custom(e)),
    }
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    match uuid::serde::compact::deserialize(d) {
      Ok(u) => Ok(u.as_bytes().to_vec()),
      Err(e) => Err(serde::de::Error::custom(e)),
    }
  }
}
