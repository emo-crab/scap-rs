use chrono::{Duration, Utc};
use diesel::{MysqlConnection, r2d2};
use diesel::r2d2::ConnectionManager;
use nvd_api::v2::LastModDate;
use nvd_api::v2::vulnerabilities::CveParameters;

pub use cli::{CPECommand, CVECommand, NVDHelper, TopLevel};
use cpe::create_cve_product;
pub use cwe::import_cwe;

use crate::cli::{EXPCommand, KBCommand, SyncCommand};
use crate::cpe::with_archive_cpe;
use crate::cve::{async_cve, with_archive_cve};
use crate::kb::{
  akb_sync, import_from_nuclei_templates_path, update_from_github, update_from_rss,
  with_archive_exploit,
};

mod cli;
mod cpe;
mod cve;
mod cwe;
pub mod error;
mod kb;

pub type Connection = MysqlConnection;
pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

pub fn init_db_pool() -> Pool {
  let database_url = dotenvy::var("DATABASE_URL").expect("DATABASE_URL must be set");
  let manager = ConnectionManager::<Connection>::new(database_url);
  Pool::builder()
    .build(manager)
    .expect("Failed to create pool.")
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

pub async fn kb_mode(config: KBCommand) {
  if config.akb {
    let _ = akb_sync().await;
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {
    // assert_eq!(result, 4);
  }
}
