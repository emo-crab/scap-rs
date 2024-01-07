mod cli;
mod import_cpe;
mod import_cve;
mod import_cwe;

use chrono::{Duration, Utc};
pub use cli::{CPECommand, CVECommand, NVDHelper, TopLevel};
use diesel::r2d2::ConnectionManager;
use diesel::{r2d2, MysqlConnection};
pub use import_cpe::{create_cve_product, create_product, create_vendor};
pub use import_cve::{import_from_api, import_from_archive};
pub use import_cwe::import_cwe;
use nvd_api::pagination::Object;
use nvd_api::v2::vulnerabilities::CveParameters;
use nvd_api::v2::LastModDate;
use nvd_api::ApiVersion;
use nvd_cpe::dictionary::CPEList;
use nvd_cves::v4::CVEContainer;
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use std::path::PathBuf;

pub type Connection = MysqlConnection;

pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

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
  for cpe_item in c.cpe_item.into_iter() {
    if cpe_item.deprecated {
      continue;
    }
    println!("{:?}", cpe_item.title);
    if let Some(references) = cpe_item.references {
      for reference in references.reference {
        println!("{:#?}", reference.href);
      }
    }
    break;
  }
}
