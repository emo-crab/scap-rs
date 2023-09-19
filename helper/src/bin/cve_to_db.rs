use cached::proc_macro::cached;
use cached::SizedCache;
use cve::impact::{ImpactMetricV2, ImpactMetricV3};
use cve::{CVEContainer, CVEItem};
use diesel::mysql::MysqlConnection;
use nvd_api::models::cve_db::CreateCve;
use nvd_api::models::cve_product_db::CreateCveProductByName;
use nvd_api::error::DBResult;
use nvd_api::models::{Cve, CveProduct, Product, Vendor};
use nvd_api::models::product_db::{CreateProduct, QueryProductById};
use nvd_api::models::vendor_db::CreateVendors;
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use std::str::FromStr;
use helper::init_db_pool;
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
fn v3(v3: &Option<ImpactMetricV3>) -> (String, f32) {
  match v3 {
    None => (String::new(), 0.0),
    Some(v) => (v.cvss_v3.vector_string.to_string(), v.cvss_v3.base_score),
  }
}
fn v2(v2: &Option<ImpactMetricV2>) -> (String, f32) {
  match v2 {
    None => (String::new(), 0.0),
    Some(v) => (v.cvss_v2.vector_string.to_string(), v.cvss_v2.base_score),
  }
}
fn import_to_db(connection: &mut MysqlConnection, cve_item: CVEItem) -> DBResult<String> {
  let id = cve_item.cve.meta.id;
  let y = id.split('-').nth(1).unwrap_or_default();
  let new_post = CreateCve {
    id: id.clone(),
    created_at: cve_item.published_date,
    updated_at: cve_item.last_modified_date,
    references: serde_json::json!(cve_item.cve.references),
    description: serde_json::json!(cve_item.cve.description),
    problem_type: serde_json::json!(cve_item.cve.problem_type),
    cvss3_vector: v3(&cve_item.impact.base_metric_v3).0,
    cvss3_score: v3(&cve_item.impact.base_metric_v3).1,
    cvss2_vector: v2(&cve_item.impact.base_metric_v2).0,
    cvss2_score: v2(&cve_item.impact.base_metric_v2).1,
    assigner: cve_item.cve.meta.assigner,
    configurations: serde_json::json!(cve_item.configurations),
    official: u8::from(true),
    year: i32::from_str(y).unwrap_or_default(),
  };
  // 插入到数据库
  match Cve::create(connection, &new_post) {
    Ok(cve_id) => {
      // 插入cpe_match关系表
      for node in cve_item.configurations.nodes {
        for vendor_product in node.vendor_product() {
          import_vendor_product_to_db(connection, vendor_product.clone());
          create_cve_product(
            connection,
            cve_id.id.clone(),
            vendor_product.vendor,
            vendor_product.product,
          );
        }
      }
    }
    Err(err) => {
      println!("Cve::create: {err:?}");
    }
  }
  Ok(new_post.id)
}

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
fn import_vendor_product_to_db(connection: &mut MysqlConnection, product: cpe::Product) -> Vec<u8> {
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
  // 构建待插入对象
  let new_post = CreateProduct {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    vendor_id: vendor,
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
fn main() {
  let connection_pool = init_db_pool();
  for y in 2002..2024 {
    let p = format!("examples/nvdcve/nvdcve-1.1-{y}.json.gz");
    println!("{p}");
    let gz_open_file = File::open(p).unwrap();
    let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
    let file = BufReader::new(gz_decoder);
    let c: CVEContainer = serde_json::from_reader(file).unwrap();
    for w in c.CVE_Items {
      import_to_db(connection_pool.get().unwrap().deref_mut(), w).unwrap_or_default();
      // break;
    }
    // break;
  }
}
