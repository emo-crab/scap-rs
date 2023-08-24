use cached::proc_macro::cached;
use cached::SizedCache;
use cve::{CVEContainer, CVEItem};
use diesel::mysql::MysqlConnection;

use nvd_db::cve::NewCve;
use nvd_db::models::Cve;
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use tools::init_db_pool;
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
#[cached(
  type = "SizedCache<String, String>",
  create = "{ SizedCache::with_size(100) }",
  convert = r#"{ format!("{}", cve_item.cve.meta.id.to_owned()) }"#
)]
fn import_to_db(connection: &mut MysqlConnection, cve_item: CVEItem) -> String {
  println!("import_to_db: {}",cve_item.cve.meta.id);
  let raw = serde_json::json!(cve_item);
  let new_post = NewCve {
    id: cve_item.cve.meta.id,
    created_at: cve_item.published_date,
    updated_at: cve_item.last_modified_date,
    references: serde_json::json!( cve_item.cve.references.reference_data),
    description: serde_json::json!(cve_item.cve.description.description_data),
    cwe: serde_json::json!(cve_item.cve.problem_type),
    cvss3_id: None,
    cvss2_id: None,
    raw,
    assigner: cve_item.cve.meta.assigner,
    configurations: serde_json::json!(cve_item.configurations.nodes),
    official: u8::from(true),
  };
  // 插入到数据库
  let _v = Cve::create(connection, &new_post).unwrap();
  new_post.id
}

fn main() {
  let connection_pool = init_db_pool();
  let gz_open_file = File::open("examples/nvdcve/nvdcve-1.1-2023.json.gz").unwrap();
  let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
  let file = BufReader::new(gz_decoder);
  let c: CVEContainer = serde_json::from_reader(file).unwrap();
  for w in c.CVE_Items {
    import_to_db(connection_pool.get().unwrap().deref_mut(), w);
    break;
  }
}
