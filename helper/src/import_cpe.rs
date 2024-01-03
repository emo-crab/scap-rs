use cached::proc_macro::cached;
use cached::SizedCache;
use diesel::mysql::MysqlConnection;
use nvd_server::modules::cve_product_db::CreateCveProductByName;
use nvd_server::modules::product_db::{CreateProduct, QueryProductById};
use nvd_server::modules::vendor_db::CreateVendors;
use nvd_server::modules::{CveProduct, Product, Vendor};
use std::collections::HashMap;

// curl --compressed https://nvd.nist.gov/vuln/data-feeds -o-|grep  -Eo '(/feeds\/[^"]*\.json\.gz)'|xargs -I % wget -c https://nvd.nist.gov%
pub fn create_cve_product(
  conn: &mut MysqlConnection,
  cve_id: String,
  vendor: String,
  product: String,
) -> String {
  // 构建待插入对象
  let cp = CreateCveProductByName {
    cve_id,
    vendor,
    product,
  };
  // 插入到数据库
  match CveProduct::create_by_name(conn, &cp) {
    Ok(_cp) => {}
    Err(err) => {
      println!("create_cve_product: {err:?}:{cp:?}");
    }
  }
  String::new()
}

#[cached(
  type = "SizedCache<String, Vec<u8>>",
  create = "{ SizedCache::with_size(100) }",
  convert = r#"{ format!("{:?}", product.to_owned()) }"#
)]
pub fn import_vendor_product_to_db(
  connection: &mut MysqlConnection,
  product: nvd_cpe::Product,
) -> Vec<u8> {
  let vendor_id = create_vendor(connection, product.vendor, None);
  create_product(connection, vendor_id, product.product, product.part)
}

#[cached(
  type = "SizedCache<String, Vec<u8>>",
  create = "{ SizedCache::with_size(100) }",
  convert = r#"{ format!("{}", name.to_owned()) }"#
)]
pub fn create_vendor(
  conn: &mut MysqlConnection,
  name: String,
  description: Option<String>,
) -> Vec<u8> {
  if let Ok(v) = Vendor::query_by_name(conn, &name) {
    return v.id;
  }
  // 构建待插入对象
  let new_post = CreateVendors {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    name,
    description,
    official: u8::from(true),
    homepage: None,
  };
  // 插入到数据库
  if let Err(err) = Vendor::create(conn, &new_post) {
    println!("create_vendor: {err:?}");
  }
  new_post.id
}

#[cached(
  type = "SizedCache<String, Vec<u8>>",
  create = "{ SizedCache::with_size(100) }",
  convert = r#"{ format!("{}:{:?}", name.to_owned(),vendor.to_owned()) }"#
)]
pub fn create_product(
  conn: &mut MysqlConnection,
  vendor: Vec<u8>,
  name: String,
  part: String,
) -> Vec<u8> {
  let q = QueryProductById {
    vendor_id: vendor.clone(),
    name: name.clone(),
  };
  if let Ok(v) = Product::query_by_id(conn, &q) {
    return v.id;
  }
  let meta: Vec<HashMap<String, Vec<String>>> = Vec::new();
  // 构建待插入对象
  let new_post = CreateProduct {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    vendor_id: vendor,
    meta: serde_json::json!(meta),
    name,
    description: None,
    official: u8::from(true),
    part,
    homepage: None,
  };
  // 插入到数据库
  if let Err(err) = Product::create(conn, &new_post) {
    println!("create_product: {err:?}");
  }
  new_post.id
}
