use cached::proc_macro::cached;
use cached::SizedCache;
use cpe::dictionary::{CPEItem, CPEList};
use diesel::mysql::MysqlConnection;
use diesel::prelude::*;
use diesel::result::Error;
use nvd_db::cpe::{NewProducts, NewVendors};
use nvd_db::models::{Product, Vendor};
use nvd_db::schema::{products, vendors};
use std::fs::File;
use std::io::BufReader;
use tools::init_db_pool;
// 建立连接
#[cached(
  type = "SizedCache<String, Vendor>",
  create = "{ SizedCache::with_size(100) }",
  convert = r#"{ format!("{}", name.to_owned()) }"#
)]
pub fn create_vendor(
  conn: &mut MysqlConnection,
  name: String,
  description: Option<String>,
) -> Vendor {
  // 构建待插入对象
  let new_post = NewVendors {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    name: name.clone(),
    description,
  };
  // 插入到数据库
  let v = diesel::insert_into(vendors::table)
    .values(&new_post)
    // MySQL does not support RETURNING clauses
    .execute(conn);
  println!("{}", name);
  vendors::dsl::vendors
    .filter(vendors::name.eq(name.clone()))
    .first(conn)
    .unwrap()
}
#[cached(
  type = "SizedCache<String, Product>",
  create = "{ SizedCache::with_size(100) }",
  convert = r#"{ format!("{}:{:?}", name.to_owned(),vendor.to_owned()) }"#
)]
pub fn create_product(conn: &mut MysqlConnection, vendor: Vec<u8>, name: String) -> Product {
  // 构建待插入对象
  let new_post = NewProducts {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    vendor_id: vendor,
    name: name.clone(),
    description: None,
  };
  // 插入到数据库
  let p = diesel::insert_into(products::table)
    .values(&new_post)
    // MySQL does not support RETURNING clauses
    .execute(conn);
  println!("{}", name);
  products::dsl::products
    .filter(products::name.eq(name.clone()))
    .first(conn)
    .unwrap()
}
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
#[cached(
  type = "SizedCache<String, Product>",
  create = "{ SizedCache::with_size(100) }",
  convert = r#"{ format!("{}:{}", vendor.to_owned(),product.to_owned()) }"#
)]
fn import_to_db(vendor: String, product: String) -> Product {
  println!("import_to_db: {}:{}", vendor, product);
  let mut connection = init_db_pool().get().unwrap();
  let vendor = create_vendor(&mut connection, vendor, None);
  create_product(&mut connection, vendor.id, product)
}
fn main() {
  let gz_open_file = File::open("examples/nvdcve/official-cpe-dictionary_v2.3.xml.gz").unwrap();
  let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
  let file = BufReader::new(gz_decoder);
  let c: CPEList = quick_xml::de::from_reader(file).unwrap();
  for cpe_item in c.cpe_item.into_iter() {
    println!("name: => {}", cpe_item.cpe23_item.name);
    import_to_db(
      cpe_item.cpe23_item.name.vendor.to_string(),
      cpe_item.cpe23_item.name.product.to_string(),
    );
  }
}
