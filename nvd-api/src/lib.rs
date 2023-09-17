pub mod error;
pub mod models;
pub mod schema;
mod routes;
mod api;

pub type DB = diesel::mysql::Mysql;
// PURGE BINARY LOGS BEFORE NOW();
