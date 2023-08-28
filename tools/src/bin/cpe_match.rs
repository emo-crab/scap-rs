use cve::{CVEContainer, CVEItem};
use diesel::mysql::MysqlConnection;

use nvd_db::cve::{CreateCve, QueryCve};
use nvd_db::models::{Cve, Cvss2, Cvss3};
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use std::str::FromStr;
use tools::init_db_pool;
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
fn import_to_db(connection: &mut MysqlConnection, cve_item: CVEItem) -> String {
    let id = cve_item.cve.meta.id;
    println!("{id}");
    // 插入到数据库
    let cve_id = Cve::query(connection, &QueryCve{
        id,
        year: None,
        official: None,
    }).unwrap();

    let configurations:cve::configurations::Configurations =serde_json::from_value(cve_id.configurations).unwrap();
    println!("{:?}",configurations);
    cve_id.id
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
            break;
        }
        break;
    }
}
