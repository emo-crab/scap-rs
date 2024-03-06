use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use nvd_cwe::weakness_catalog::WeaknessCatalog;
use nvd_cwe::weaknesses::Weakness;
use nvd_model::cwe::db::{CreateCwe, UpdateCwe};
use nvd_model::cwe::Cwe;
use nvd_model::Connection;

use crate::init_db_pool;

// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
fn import_cwe_from_archive(connection: &mut Connection, w: Weakness) -> i32 {
  let new_post = CreateCwe {
    id: w.id,
    name: w.name,
    description: w.description,
    status: format!("{:?}", w.status),
  };
  // 插入到数据库
  let _v = Cwe::create(connection, &new_post);
  new_post.id
}

pub fn import_cwe(path: PathBuf) {
  let connection_pool = init_db_pool();
  let zip_open_file = File::open(path).unwrap();
  let mut zip_archive = zip::ZipArchive::new(zip_open_file).unwrap();
  let file = BufReader::new(zip_archive.by_index(0).unwrap());
  let c: WeaknessCatalog = quick_xml::de::from_reader(file).unwrap();
  for w in c.weaknesses.weaknesses {
    import_cwe_from_archive(connection_pool.get().unwrap().deref_mut(), w);
  }
}

// 中文CWE
#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
struct ZhCwe {
  id: i32,
  name_zh: String,
  description_zh: String,
  remediation: String,
}

pub fn update_zh_cwe(path: PathBuf) {
  let json_open_file = File::open(path).unwrap();
  let zh_cwe_list: Vec<ZhCwe> = serde_json::from_reader(json_open_file).unwrap();
  let connection_pool = init_db_pool();
  for zh_cwe in zh_cwe_list {
    let new_post = UpdateCwe {
      id: zh_cwe.id,
      name_zh: zh_cwe.name_zh,
      description_zh: zh_cwe.description_zh,
      remediation: zh_cwe.remediation.trim().to_string(),
    };
    let v = Cwe::update(connection_pool.get().unwrap().deref_mut(), &new_post);
    println!("{:?}", v);
  }
}
