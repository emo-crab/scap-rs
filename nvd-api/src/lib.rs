pub mod api;
pub mod error;
pub mod modules;
pub mod schema;

use crate::error::NVDApiError;
use actix_web::HttpResponse;
use diesel::r2d2::ConnectionManager;
use diesel::{r2d2, MysqlConnection};

pub type DB = diesel::mysql::Mysql;
pub type Connection = MysqlConnection;
// PURGE BINARY LOGS BEFORE NOW();
pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;
pub type ApiResponse = Result<HttpResponse, NVDApiError>;
pub fn init_db_pool() -> Pool {
  let database_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL must be set");
  let manager = ConnectionManager::<Connection>::new(database_url);
  r2d2::Pool::builder()
    .build(manager)
    .expect("Failed to create pool.")
}
