use cached::proc_macro::cached;
use cached::SizedCache;
use cpe::dictionary::CPEList;
use diesel::mysql::MysqlConnection;
use diesel::prelude::*;

use nvd_db::cpe::{NewProducts, NewVendors};
use nvd_db::models::{Product, Vendor};
use nvd_db::schema::{products, vendors};
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use tools::init_db_pool;
// 建立连接
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
  // 构建待插入对象
  let new_post = NewVendors {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    name: name.clone(),
    description,
    official: u8::from(true),
  };
  // 插入到数据库
  let v = diesel::insert_into(vendors::table)
    .values(&new_post)
    // MySQL does not support RETURNING clauses
    .execute(conn);
  if let Err(_err) = v {
    let ve: Vendor = vendors::dsl::vendors
      .filter(vendors::name.eq(name))
      .first(conn)
      .unwrap();
    return ve.id;
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
  // 构建待插入对象
  let new_post = NewProducts {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    vendor_id: vendor,
    name: name.clone(),
    description: None,
    official: u8::from(true),
    part,
  };
  // 插入到数据库
  let p = diesel::insert_into(products::table)
    .values(&new_post)
    // MySQL does not support RETURNING clauses
    .execute(conn);
  if let Err(_err) = p {
    let prod: Product = products::dsl::products
      .filter(products::name.eq(name))
      .first(conn)
      .unwrap();
    return prod.id;
  }
  new_post.id
}
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
#[cached(
  type = "SizedCache<String, Vec<u8>>",
  create = "{ SizedCache::with_size(100) }",
  convert = r#"{ format!("{}:{}", vendor.to_owned(),product.to_owned()) }"#
)]
fn import_to_db(
  connection: &mut MysqlConnection,
  vendor: String,
  product: String,
  part: String,
) -> Vec<u8> {
  println!("import_to_db: {vendor}:{product}");
  let vendor_id = create_vendor(connection, vendor, None);
  create_product(connection, vendor_id, product, part)
}

fn main() {
  let connection_pool = init_db_pool();
  let gz_open_file = File::open("examples/nvdcve/official-cpe-dictionary_v2.3.xml.gz").unwrap();
  let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
  let file = BufReader::new(gz_decoder);
  let c: CPEList = quick_xml::de::from_reader(file).unwrap();
  let mut flag = false;
  for cpe_item in c.cpe_item.into_iter() {
    let vendor = cpe_item.cpe23_item.name.vendor.to_string();
    if cpe_item.deprecated {
      continue;
    }
    if flag {
      import_to_db(
        connection_pool.get().unwrap().deref_mut(),
        cpe_item.cpe23_item.name.vendor.to_string(),
        cpe_item.cpe23_item.name.product.to_string(),
        cpe_item.cpe23_item.name.part.to_string(),
      );
      continue;
    }
    if vendor.starts_with('g') {
      flag = true;
      import_to_db(
        connection_pool.get().unwrap().deref_mut(),
        cpe_item.cpe23_item.name.vendor.to_string(),
        cpe_item.cpe23_item.name.product.to_string(),
        cpe_item.cpe23_item.name.part.to_string(),
      );
    }

    // break;
  }
}
