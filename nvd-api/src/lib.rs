pub mod error;
pub mod models;
pub mod schema;
pub type DB = diesel::mysql::Mysql;
// PURGE BINARY LOGS BEFORE NOW();
