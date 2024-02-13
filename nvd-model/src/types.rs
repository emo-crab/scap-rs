use std::collections::HashMap;
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
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(AsExpression, FromSqlRow), diesel(sql_type = Json))]
#[serde(transparent)]
pub struct AnyValue<T: Clone>
where
  T: Clone,
{
  inner: T,
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
pub type MetaType = HashMap<String, HashMap<String, String>>;

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(transparent)]
pub struct MetaData {
  pub inner: MetaType,
}

impl MetaData {
  pub fn from_hashmap(name: String, hm: HashMap<String, String>) -> MetaData {
    let mut i = MetaType::new();
    i.insert(name, hm);
    MetaData { inner: i }
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
