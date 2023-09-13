use nvd_db::cve::QueryCve;
use nvd_db::models::{Cve, CveProduct, Product, Vendor};
use nvd_db::product::QueryProduct;
use nvd_db::vendor::QueryVendor;
use std::ops::DerefMut;
use nvd_db::cve_product::QueryCveProduct;
use tools::init_db_pool;

fn main() {
  query_cve();
}

fn query_vendor() {
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
fn query_product() {
  let connection_pool = init_db_pool();
  let c = Product::query(
    connection_pool.get().unwrap().deref_mut(),
    &QueryProduct {
      vendor_name: Some("php".to_string()),
      name: None,
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
      id: Some("CVE-2020-7354".to_string()),
      year: None,
      official: None,
      vendor: None,
      product: Some("metasploit".to_string()),
      severity: None,
      limit: 20,
      offset: 0,
    },
  )
  .unwrap();
  for result in c.result{
    println!("{:#}", serde_json::to_string_pretty(&result.id).unwrap());
  }

}

fn query_cve_by_product() {
  let connection_pool = init_db_pool();
  let c = CveProduct::query(
    connection_pool.get().unwrap().deref_mut(),
    &QueryCveProduct {
      cve_id: None,
      vendor: None,
      product: Some("exchange".to_string()),
      limit: 3,
      offset: 0,
    },
  ).unwrap();
  println!("{:#}", serde_json::to_string_pretty(&c).unwrap());
}