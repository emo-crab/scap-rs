use cached::proc_macro::cached;
use cached::SizedCache;
use diesel::mysql::MysqlConnection;
use nvd_cves::v4::CVEItem;
use nvd_server::error::DBResult;
use nvd_server::modules::cve_db::CreateCve;
use nvd_server::modules::cve_product_db::CreateCveProductByName;
use nvd_server::modules::product_db::{CreateProduct, QueryProductById};
use nvd_server::modules::vendor_db::CreateVendors;
use nvd_server::modules::{Cve, CveProduct, Product, Vendor};
use std::collections::HashSet;
use std::str::FromStr;

// curl --compressed https://nvd.nist.gov/vuln/data-feeds -o-|grep  -Eo '(/feeds\/[^"]*\.json\.gz)'|xargs -I % wget -c https://nvd.nist.gov%
fn create_cve_product(
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
fn import_vendor_product_to_db(
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
fn create_vendor(conn: &mut MysqlConnection, name: String, description: Option<String>) -> Vec<u8> {
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
fn create_product(
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

pub fn import_from_archive(
  connection: &mut MysqlConnection,
  cve_item: CVEItem,
) -> DBResult<String> {
  let id = cve_item.cve.meta.id;
  let y = id.split('-').nth(1).unwrap_or_default();
  let new_post = CreateCve {
    id: id.clone(),
    created_at: cve_item.published_date,
    updated_at: cve_item.last_modified_date,
    references: serde_json::json!(cve_item.cve.references.reference_data),
    description: serde_json::json!(cve_item.cve.description.description_data),
    severity: cve_item.impact.severity().to_lowercase(),
    metrics: serde_json::json!(cve_item.impact),
    assigner: cve_item.cve.meta.assigner,
    configurations: serde_json::json!(cve_item.configurations.nodes),
    year: i32::from_str(y).unwrap_or_default(),
    weaknesses: serde_json::json!(cve_item.cve.problem_type.problem_type_data),
    timeline: Default::default(),
  };
  // 插入到数据库
  match Cve::create(connection, &new_post) {
    Ok(cve_id) => {
      // 插入cpe_match关系表
      for vendor_product in cve_item
        .configurations
        .nodes
        .iter()
        .flat_map(|n| n.vendor_product())
        .collect::<HashSet<_>>()
      {
        import_vendor_product_to_db(connection, vendor_product.clone());
        create_cve_product(
          connection,
          cve_id.id.clone(),
          vendor_product.vendor,
          vendor_product.product,
        );
      }
    }
    Err(err) => {
      println!("Cve::create: {err:?}");
    }
  }
  Ok(new_post.id)
}

pub fn import_from_api(
  connection: &mut MysqlConnection,
  cve_item: nvd_cves::api::CVE,
) -> DBResult<String> {
  let id = cve_item.id;
  let y = id.split('-').nth(1).unwrap_or_default();
  let configurations = cve_item
    .configurations
    .iter()
    .flat_map(|n| n.nodes.clone())
    .collect::<Vec<nvd_cves::v4::configurations::Node>>();
  // println!("{:?}", configurations);
  let new_post = CreateCve {
    id: id.clone(),
    created_at: cve_item.published,
    updated_at: cve_item.last_modified,
    references: serde_json::json!(cve_item.references),
    description: serde_json::json!(cve_item.descriptions),
    severity: cve_item.metrics.severity().to_lowercase(),
    metrics: serde_json::json!(cve_item.metrics),
    assigner: cve_item.source_identifier,
    configurations: serde_json::json!(configurations),
    year: i32::from_str(y).unwrap_or_default(),
    weaknesses: serde_json::json!(cve_item.weaknesses),
    timeline: Default::default(),
  };
  // 插入或者更新到数据库
  match Cve::create_or_update(connection, &new_post) {
    Ok(cve_id) => {
      // 插入cpe_match关系表
      for vendor_product in configurations
        .iter()
        .flat_map(|n| n.vendor_product())
        .collect::<HashSet<_>>()
      {
        import_vendor_product_to_db(connection, vendor_product.clone());
        create_cve_product(
          connection,
          cve_id.id.clone(),
          vendor_product.vendor,
          vendor_product.product,
        );
      }
    }
    Err(err) => {
      println!("Cve::create_or_update: {err:?}");
    }
  }
  Ok(new_post.id)
}
