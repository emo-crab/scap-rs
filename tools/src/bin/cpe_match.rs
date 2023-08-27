use cve::{CVEContainer, CVEItem};
use diesel::mysql::MysqlConnection;

use nvd_db::cve::NewCve;
use nvd_db::models::{Cve, Cvss2, Cvss3};
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use std::str::FromStr;
use tools::init_db_pool;
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
fn import_to_db(connection: &mut MysqlConnection, cve_item: CVEItem) -> String {
    let raw = serde_json::json!(cve_item);
    let id = cve_item.cve.meta.id;
    let y = id.split('-').nth(1).unwrap_or_default();
    println!("{id}");
    let new_post = NewCve {
        id: id.clone(),
        created_at: cve_item.published_date,
        updated_at: cve_item.last_modified_date,
        references: serde_json::json!(cve_item.cve.references.reference_data),
        description: serde_json::json!(cve_item.cve.description.description_data),
        cwe: serde_json::json!(cve_item.cve.problem_type),
        cvss3_id: Cvss3::create_from_impact(connection, cve_item.impact.base_metric_v3),
        cvss2_id: Cvss2::create_from_impact(connection, cve_item.impact.base_metric_v2),
        raw,
        assigner: cve_item.cve.meta.assigner,
        configurations: serde_json::json!(cve_item.configurations.nodes),
        official: u8::from(true),
        year: i32::from_str(y).unwrap_or_default(),
    };
    // 插入到数据库
    let _v = Cve::create(connection, &new_post).unwrap();
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
            import_to_db(connection_pool.get().unwrap().deref_mut(), w);
        }
    }
}
