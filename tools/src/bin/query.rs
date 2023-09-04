use nvd_db::cve::QueryCve;
use nvd_db::models::Cve;
use std::ops::DerefMut;
use tools::init_db_pool;

fn main() {
  let connection_pool = init_db_pool();
  let c = Cve::query_with_cvss(
    connection_pool.get().unwrap().deref_mut(),
    &QueryCve {
      id: "CVE-2007-5928".to_string(),
      year: None,
      official: None,
    },
  ).unwrap();
  println!("{:#}", serde_json::to_string_pretty(&c).unwrap());
}
