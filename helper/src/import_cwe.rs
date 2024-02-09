use crate::init_db_pool;
use diesel::MysqlConnection;
use nvd_cwe::weakness_catalog::WeaknessCatalog;
use nvd_cwe::weaknesses::Weakness;
use nvd_model::cwe::db::CreateCwe;
use nvd_model::cwe::Cwe;
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%

fn import_cwe_from_archive(connection: &mut MysqlConnection, w: Weakness) -> i32 {
  let new_post = CreateCwe {
    id: w.id,
    name: w.name,
    description: w.description,
  };
  // 插入到数据库
  let _v = Cwe::create(connection, &new_post);
  new_post.id
}

pub fn import_cwe() {
  let connection_pool = init_db_pool();
  let zip_open_file = File::open("helper/examples/nvdcwe/cwec_latest.xml.zip").unwrap();
  let mut zip_archive = zip::ZipArchive::new(zip_open_file).unwrap();
  let file = BufReader::new(zip_archive.by_index(0).unwrap());
  let c: WeaknessCatalog = quick_xml::de::from_reader(file).unwrap();
  for w in c.weaknesses.weaknesses {
    import_cwe_from_archive(connection_pool.get().unwrap().deref_mut(), w);
  }
}
