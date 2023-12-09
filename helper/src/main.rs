use chrono::{Duration, Utc};
use nvd_cves::v4::CVEContainer;
use helper::{import_from_api, import_from_archive, init_db_pool};
use nvd_api::pagination::Object;
use nvd_api::v2::vulnerabilities::CveParameters;
use nvd_api::v2::LastModDate;
use nvd_api::ApiVersion;
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;

#[tokio::main]
async fn main() {
  // import_cwe();
  // with_archive();
  // std::process::exit(0);

  let connection_pool = init_db_pool();
  let api = nvd_api::NVDApi::new(None, ApiVersion::default()).unwrap();
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
  let resp = api.cve(param).await.unwrap();
  if let Object::Vulnerabilities(vs) = resp.results {
    for v in vs {
      println!("正在同步：{:?} {:?}", v.cve.vuln_status, v.cve.id);
      import_from_api(connection_pool.get().unwrap().deref_mut(), v.cve).unwrap();
    }
  }
}

fn with_archive() {
  let connection_pool = init_db_pool();
  for y in (2002..2024).rev() {
    let p = format!("helper/examples/nvdcve/nvdcve-1.1-{y}.json.gz");
    println!("{p}");
    let gz_open_file = File::open(p).unwrap();
    let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
    let file = BufReader::new(gz_decoder);
    let c: CVEContainer = serde_json::from_reader(file).unwrap();
    for w in c.CVE_Items {
      import_from_archive(connection_pool.get().unwrap().deref_mut(), w).unwrap_or_default();
    }
    // break;
  }
}
