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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(AsExpression, FromSqlRow), diesel(sql_type = Json))]
#[serde(untagged)]
pub enum AnyValue<T: Clone>
where
  T: Clone,
{
  Value(serde_json::Value),
  Any(T),
}

impl<T: Default + for<'de> serde::Deserialize<'de> + Clone> AnyValue<T> {
  pub fn into_inner(self) -> T {
    match self {
      AnyValue::Value(v) => serde_json::from_value(v.clone()).unwrap_or_default(),
      AnyValue::Any(a) => a,
    }
  }
  pub fn inner(&self) -> T {
    match (*self).clone() {
      AnyValue::Value(v) => serde_json::from_value(v.clone()).unwrap_or_default(),
      AnyValue::Any(a) => a,
    }
  }
}

impl<T: Default + Clone> Default for AnyValue<T> {
  fn default() -> Self {
    AnyValue::Any(T::default())
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
    let value = serde_json::to_value(self)?;
    <serde_json::Value as ToSql<Json, DB>>::to_sql(&value, &mut out.reborrow())
  }
}
