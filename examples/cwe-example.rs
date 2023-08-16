use std::fs::File;
use std::io::BufReader;
use cwe::weakness_catalog::WeaknessCatalog;

// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%

fn main() {
  let zip_open_file = File::open("examples/nvdcwe/1387.xml.zip").unwrap();
  let mut zip_archive = zip::ZipArchive::new(zip_open_file).unwrap();
  let file = BufReader::new(zip_archive.by_index(0).unwrap());
  let c: WeaknessCatalog = quick_xml::de::from_reader(file).unwrap();
  println!("{:#?}", &c.external_references);
  let data = serde_json::to_string_pretty(&c).unwrap();
  println!("{}",data);
}
