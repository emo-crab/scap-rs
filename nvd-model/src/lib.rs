#[cfg(feature = "db")]
use diesel::{r2d2, r2d2::ConnectionManager, MysqlConnection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// wubba lubba dub dub
// 后端和前端特性不能同时开启
// #[cfg(all(feature = "db", feature = "yew"))]
// compile_error!("feature \"db\" and feature \"yew\" cannot be enabled at the same time");

pub mod cve;
pub mod cve_exploit;
pub mod cve_product;
pub mod cwe;
#[cfg(feature = "db")]
pub mod error;
pub mod exploit;
pub mod pagination;
pub mod product;
#[cfg(feature = "db")]
pub mod schema;
pub mod types;
pub mod vendor;

#[cfg(feature = "db")]
pub type DB = diesel::mysql::Mysql;
#[cfg(feature = "db")]
pub type Connection = MysqlConnection;
// PURGE BINARY LOGS BEFORE NOW();
#[cfg(feature = "db")]
pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

#[cfg(feature = "db")]
pub fn init_db_pool() -> Pool {
  let database_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL must be set");
  let manager = ConnectionManager::<Connection>::new(database_url);
  r2d2::Pool::builder()
    .build(manager)
    .expect("Failed to create pool.")
}

pub type MetaType = HashMap<String, HashMap<String, String>>;

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
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

// 将公共的数据结构放在这里
pub fn add(left: usize, right: usize) -> usize {
  left + right
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let result = add(2, 2);
    assert_eq!(result, 4);
  }
}
