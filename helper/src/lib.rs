use std::ops::DerefMut;

use chrono::{Duration, Utc};
use diesel::r2d2::ConnectionManager;
use diesel::{r2d2, MysqlConnection};
use nvd_api::pagination::Object;
use nvd_api::v2::vulnerabilities::CveParameters;
use nvd_api::v2::LastModDate;
use nvd_api::ApiVersion;

use crate::cli::{EXPCommand, SyncCommand};
use crate::import_cpe::with_archive_cpe;
use crate::import_cve::with_archive_cve;
use crate::import_exploit::{
  import_from_nuclei_templates_path, update_from_github, update_from_rss, with_archive_exploit,
};
pub use cli::{CPECommand, CVECommand, NVDHelper, TopLevel};
pub use import_cpe::{create_cve_product, create_product, create_vendor};
pub use import_cve::{import_from_api, import_from_archive};
pub use import_cwe::import_cwe;

mod cli;
mod import_cpe;
mod import_cve;
mod import_cwe;
mod import_exploit;

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

pub async fn exploit_mode(config: EXPCommand) {
  if let Some(path) = config.path {
    with_archive_exploit(path)
  }
  if config.api {
    update_from_github().await;
  }
  if let Some(path) = config.template {
    import_from_nuclei_templates_path(path)
  }
}

pub async fn sync_mode(config: SyncCommand) {
  if config.cve {
    let now = Utc::now();
    // 每两个小时拉取三小时内的更新数据入库
    let three_hours = now - Duration::hours(3);
    let param = CveParameters {
      last_mod: Some(LastModDate {
        last_mod_start_date: three_hours.to_rfc3339(),
        last_mod_end_date: now.to_rfc3339(),
      }),
      ..CveParameters::default()
    };
    println!(
      "开始更新从{}到{}的cve",
      three_hours.to_rfc3339(),
      now.to_rfc3339()
    );
    async_cve(param).await
  }
  if config.exp {
    update_from_rss().await;
    update_from_github().await;
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {
    // assert_eq!(result, 4);
  }
}
