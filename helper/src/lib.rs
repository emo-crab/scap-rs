use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use std::path::PathBuf;

use chrono::{Duration, Utc};
use diesel::r2d2::ConnectionManager;
use diesel::{r2d2, MysqlConnection};
use nvd_api::pagination::Object;
use nvd_api::v2::vulnerabilities::CveParameters;
use nvd_api::v2::LastModDate;
use nvd_api::ApiVersion;

pub use cli::{CPECommand, CVECommand, NVDHelper, TopLevel};
pub use import_cpe::{create_cve_product, create_product, create_vendor};
pub use import_cve::{import_from_api, import_from_archive};
pub use import_cwe::import_cwe;
use nvd_cpe::dictionary::CPEList;
use nvd_cves::v4::CVEContainer;
use nvd_server::modules::product_db::UpdateProduct;

use crate::import_cpe::update_products;

mod cli;
mod import_cpe;
mod import_cve;
mod import_cwe;

pub type Connection = MysqlConnection;
pub type MetaType = HashMap<String, HashMap<String, String>>;
pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

pub struct Meta {
  inner: MetaType,
}

impl Meta {
  pub fn from_hashmap(name: String, hm: HashMap<String, String>) -> Meta {
    let mut i = MetaType::new();
    i.insert(name, hm);
    Meta { inner: i }
  }
}

pub fn init_db_pool() -> Pool {
  let database_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL must be set");
  let manager = ConnectionManager::<Connection>::new(database_url);
  Pool::builder()
    .build(manager)
    .expect("Failed to create pool.")
}

async fn async_cve(param: CveParameters) {
  let connection_pool = init_db_pool();
  let api = nvd_api::NVDApi::new(None, ApiVersion::default()).unwrap();
  let resp = api.cve(param).await.unwrap();
  if let Object::Vulnerabilities(vs) = resp.results {
    for v in vs {
      println!("正在同步：{:?} {:?}", v.cve.vuln_status, v.cve.id);
      import_from_api(connection_pool.get().unwrap().deref_mut(), v.cve).unwrap();
    }
  }
}

fn with_archive_cve(path: PathBuf) {
  let connection_pool = init_db_pool();
  let gz_open_file = File::open(path).unwrap();
  let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
  let file = BufReader::new(gz_decoder);
  let c: CVEContainer = serde_json::from_reader(file).unwrap();
  for w in c.CVE_Items {
    import_from_archive(connection_pool.get().unwrap().deref_mut(), w).unwrap_or_default();
  }
}

pub async fn cve_mode(config: CVECommand) {
  if let Some(p) = config.path {
    with_archive_cve(p)
  }
  if config.api || config.id.is_some() {
    let mut param = CveParameters {
      cve_id: config.id,
      ..CveParameters::default()
    };
    if let Some(hours) = config.hours {
      let now = Utc::now();
      // 每两个小时拉取三小时内的更新数据入库
      let three_hours = now - Duration::hours(hours);
      param = CveParameters {
        last_mod: Some(LastModDate {
          last_mod_start_date: three_hours.to_rfc3339(),
          last_mod_end_date: now.to_rfc3339(),
        }),
        ..param
      };
    }
    async_cve(param).await
  }
}

pub async fn cpe_mode(config: CPECommand) {
  if let Some(path) = config.path {
    with_archive_cpe(path)
  }
}

fn with_archive_cpe(path: PathBuf) {
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

fn get_title(titles: Vec<nvd_cpe::dictionary::Title>) -> Option<String> {
  let title_map: HashMap<String, f32> = titles.iter().map(|t| (t.value.clone(), 0.0)).collect();
  merge_diff(title_map)
}

fn get_href(hrefs: Vec<nvd_cpe::dictionary::Reference>) -> MetaType {
  let mut href_map: HashMap<String, String> = HashMap::new();
  for href in hrefs {
    href_map.entry(href.href).or_insert(href.value);
  }
  Meta::from_hashmap("references".to_string(), href_map).inner
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

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {
    // assert_eq!(result, 4);
  }
}
