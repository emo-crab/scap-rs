use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use std::path::PathBuf;

use cached::proc_macro::cached;
use cached::SizedCache;
use diesel::mysql::MysqlConnection;
use nvd_cpe::dictionary::CPEList;
use nvd_model::cve_product::db::CreateCveProductByName;
use nvd_model::cve_product::CveProduct;
use nvd_model::error::DBResult;
use nvd_model::product::db::{
  CreateProduct, QueryProductById, QueryProductByVendorName, UpdateProduct,
};
use nvd_model::product::Product;
use nvd_model::vendor::db::CreateVendors;
use nvd_model::vendor::Vendor;
use nvd_model::MetaData;

pub type MetaType = HashMap<String, HashMap<String, String>>;
use crate::init_db_pool;

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
  let meta: MetaType = HashMap::new();
  let new_post = CreateVendors {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    name,
    description,
    meta: serde_json::json!(meta),
    official: u8::from(true),
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
  let meta: MetaType = HashMap::new();
  // 构建待插入对象
  let new_post = CreateProduct {
    id: uuid::Uuid::new_v4().as_bytes().to_vec(),
    vendor_id: vendor,
    meta: serde_json::json!(meta),
    name,
    description: None,
    official: u8::from(true),
    part,
  };
  // 插入到数据库
  if let Err(err) = Product::create(conn, &new_post) {
    println!("create_product: {err:?}");
  }
  new_post.id
}

// 删除过期的CVE编号和产品关联关系
pub fn del_expire_product(conn: &mut MysqlConnection, id: String, product_set: HashSet<Vec<u8>>) {
  if let Ok(cve_products) = CveProduct::query_product_by_cve(conn, id.clone()) {
    let remote_set: HashSet<Vec<u8>> = HashSet::from_iter(cve_products);
    for p in remote_set.difference(&product_set) {
      if let Err(err) = CveProduct::delete(conn, id.clone(), p.clone()) {
        println!("delete product err: {:?}", err);
      }
    }
  }
}

// 更新产品描述和元数据链接信息
pub fn update_products(conn: &mut MysqlConnection, args: UpdateProduct) -> DBResult<Product> {
  let vp = QueryProductByVendorName {
    vendor_name: args.vendor_name.clone(),
    name: args.name.clone(),
  };
  // 查供应商id
  let p = Product::query_by_vendor_name(conn, &vp)?;
  let args = UpdateProduct {
    id: p.id,
    vendor_id: p.vendor_id,
    ..args
  };
  Product::update(conn, &args)
}

fn get_title(titles: Vec<nvd_cpe::dictionary::Title>) -> Option<String> {
  let title_map: HashMap<String, f32> = titles.iter().map(|t| (t.value.clone(), 0.0)).collect();
  merge_diff(title_map)
}

fn get_href(hrefs: Vec<nvd_cpe::dictionary::Reference>) -> MetaType {
  let mut href_map: HashMap<String, String> = HashMap::new();
  for href in hrefs {
    href_map.entry(href.href).or_insert(href.value);
  }
  MetaData::from_hashmap("references".to_string(), href_map).inner
}

// 从多个相似字符串提取相同信息，合并为一个字符串
fn merge_diff(diff_map: HashMap<String, f32>) -> Option<String> {
  let mut diff_map = diff_map;
  if diff_map.is_empty() {
    return None;
  }
  let backup = diff_map.clone();
  while diff_map.len() != 1 {
    let title_list: Vec<String> = diff_map.keys().map(|k| k.to_string()).collect();
    diff_map.clear();
    for (title_index_new, title_new) in title_list.iter().enumerate() {
      for (title_index_old, title_old) in title_list.iter().enumerate() {
        if title_index_new < title_index_old {
          let v1s: Vec<&str> = title_new.split_ascii_whitespace().collect();
          let v2s: Vec<&str> = title_old.split_ascii_whitespace().collect();
          let diffs = similar::TextDiff::from_slices(&v1s, &v2s);
          if diffs.ratio() < 0.5 {
            continue;
          }
          let mut merge = vec![];
          for diff in diffs.iter_all_changes() {
            if diff.tag() == similar::ChangeTag::Equal {
              merge.push(diff.value());
            }
          }
          diff_map.insert(merge.join(" "), diffs.ratio());
        }
      }
    }
    if diff_map.is_empty() {
      break;
    }
  }
  if diff_map.is_empty() {
    diff_map = backup;
  }
  return diff_map.keys().next().map(|k| k.to_string());
}

pub fn with_archive_cpe(path: PathBuf) {
  let gz_open_file = File::open(path).unwrap();
  let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
  let file = BufReader::new(gz_decoder);
  let c: CPEList = quick_xml::de::from_reader(file).unwrap();
  let mut current = None;
  let mut all_references = vec![];
  let mut all_titles = vec![];
  let connection_pool = init_db_pool();
  for cpe_item in c.cpe_item.into_iter() {
    let product = nvd_cpe::Product::from(&cpe_item.cpe23_item.name);
    if cpe_item.deprecated {
      continue;
    }
    // 如果当前产品和上一个产品一样，合并
    if current == Some(product.clone()) {
      if let Some(references) = cpe_item.references {
        all_references.extend(references.reference);
      }
      all_titles.extend(cpe_item.title)
    } else if current.is_none() {
      // 初始化，第一次的
      current = Some(product.clone());
      if let Some(references) = cpe_item.references {
        all_references.extend(references.reference);
      }
      all_titles.extend(cpe_item.title)
    } else {
      // 当这次的产品和上面的不一样，说明要更新了
      let current_product = current.unwrap();
      let description = get_title(all_titles);
      let meta = get_href(all_references);
      if let Ok(p) = update_products(
        connection_pool.get().unwrap().deref_mut(),
        UpdateProduct {
          id: vec![],
          vendor_id: vec![],
          vendor_name: current_product.vendor,
          meta: serde_json::json!(meta),
          name: current_product.product,
          description,
        },
      ) {
        println!("更新产品：{}", p.name);
      }
      all_references = vec![];
      all_titles = vec![];
      current = Some(product.clone());
    }
  }
}
