use diesel::{MysqlConnection, r2d2};
use diesel::r2d2::ConnectionManager;

pub type Connection = MysqlConnection;

pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

pub fn init_db_pool() -> Pool {
    let database_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<Connection>::new(database_url);
    
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}