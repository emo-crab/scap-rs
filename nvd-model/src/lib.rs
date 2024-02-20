#[cfg(feature = "db")]
use diesel::{r2d2, r2d2::ConnectionManager, MysqlConnection};

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
pub mod knowledge_base;
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

// 将公共的数据结构放在这里
pub fn add(left: usize, right: usize) -> usize {
  left + right
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
