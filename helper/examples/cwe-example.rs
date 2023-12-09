use nvd_cwe::weakness_catalog::WeaknessCatalog;
use std::fs::File;
use std::io::BufReader;

// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%

fn main() {
  let zip_open_file = File::open("examples/nvdcwe/cwec_latest.xml.zip").unwrap();
  let mut zip_archive = zip::ZipArchive::new(zip_open_file).unwrap();
  let file = BufReader::new(zip_archive.by_index(0).unwrap());
  let c: WeaknessCatalog = quick_xml::de::from_reader(file).unwrap();
  for w in c.weaknesses.weaknesses {
    // let data = serde_json::to_string_pretty(&w).unwrap();
    if w.name.len() > 128 {
      println!("{}", w.name);
    }
  }
}
