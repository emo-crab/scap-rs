use cwe::weakness_catalog::WeaknessCatalog;
use diesel::mysql::MysqlConnection;
use nvd_api::models::cwe_db::CreateCwe;
use nvd_api::models::Cwe;
use std::fs::File;
use std::io::BufReader;
use std::ops::DerefMut;
use helper::init_db_pool;
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
fn import_to_db(
  connection: &mut MysqlConnection,
  id: i32,
  name: String,
  description: String,
) -> i32 {
  println!("import_to_db: {id}:{name}");
  let new_post = CreateCwe {
    id,
    name,
    description,
  };
  // 插入到数据库
  let _v = Cwe::create(connection, &new_post);
  new_post.id
}

fn main() {
  let connection_pool = init_db_pool();
  let zip_open_file = File::open("examples/nvdcwe/cwec_latest.xml.zip").unwrap();
  let mut zip_archive = zip::ZipArchive::new(zip_open_file).unwrap();
  let file = BufReader::new(zip_archive.by_index(0).unwrap());
  let c: WeaknessCatalog = quick_xml::de::from_reader(file).unwrap();
  for w in c.weaknesses.weaknesses {
    import_to_db(
      connection_pool.get().unwrap().deref_mut(),
      w.id,
      w.name,
      w.description,
    );
  }
}
