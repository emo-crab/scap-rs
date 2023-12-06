mod import_cve;
mod import_cwe;

use diesel::r2d2::ConnectionManager;
use diesel::{r2d2, MysqlConnection};
pub use import_cve::{import_from_api, import_from_archive};
pub use import_cwe::import_cwe;
pub type Connection = MysqlConnection;

pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

pub fn init_db_pool() -> Pool {
  let database_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL must be set");
  let manager = ConnectionManager::<Connection>::new(database_url);
  Pool::builder()
    .build(manager)
    .expect("Failed to create pool.")
}
