use nvd_api::models::cve_db::QueryCve;
use nvd_api::models::cve_product_db::QueryCveProduct;
use nvd_api::models::{Cve, CveProduct, Product, Vendor};
use nvd_api::models::product_db::QueryProduct;
use nvd_api::models::vendor_db::QueryVendor;
use std::ops::DerefMut;
use helper::init_db_pool;

fn main() {
  query_vendor();
}

fn query_vendor() {
  let connection_pool = init_db_pool();
  let c = Vendor::query(
    connection_pool.get().unwrap().deref_mut(),
    &QueryVendor {
      name: Some("php".to_string()),
      official: None,
      limit: Some(10),
      offset: Some(0),
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
      part: None,
      official: None,
      limit: Some(10),
      offset: Some(0),
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
      year: None,
      official: None,
      vendor: None,
      product: Some("open-vm-tools".to_string()),
      severity: Some("High".to_string()),
      limit: Some(1000),
      offset: Some(0),
    },
  )
  .unwrap();
  println!("{}", c.total);
  for result in c.result {
    println!(
      "{}: {}:{}",
      result.id, result.cvss2_score, result.cvss3_score
    );
    // println!("{:#}", serde_json::to_string_pretty(&result.cvss3_score).unwrap());
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
      limit: Some(3),
      offset: Some(0),
    },
  )
  .unwrap();
  println!("{:#}", serde_json::to_string_pretty(&c).unwrap());
}
