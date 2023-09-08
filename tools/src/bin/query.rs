use nvd_db::cve::QueryCve;
use nvd_db::models::{Cve, Product, Vendor};
use nvd_db::product::QueryProduct;
use nvd_db::vendor::QueryVendor;
use std::ops::DerefMut;
use tools::init_db_pool;

fn main() {
  let connection_pool = init_db_pool();
  let c = Vendor::query(
    connection_pool.get().unwrap().deref_mut(),
    &QueryVendor {
      name: Some("php".to_string()),
      official: None,
      limit: 10,
      offset: 0,
    },
  )
  .unwrap();
  println!("{:#}", serde_json::to_string_pretty(&c).unwrap());
}

fn query_cve() {
  let connection_pool = init_db_pool();
  let c = Cve::query(
    connection_pool.get().unwrap().deref_mut(),
    &QueryCve {
      id: None,
      year: Some(2014),
      official: None,
      limit: 3,
      offset: 0,
    },
  )
  .unwrap();
  println!("{:#}", serde_json::to_string_pretty(&c).unwrap());
}
