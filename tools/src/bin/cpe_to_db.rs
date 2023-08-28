use cpe::dictionary::CPEList;

use std::fs::File;
use std::io::BufReader;

// 建立连接

// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%

fn main() {
  let gz_open_file = File::open("examples/nvdcve/official-cpe-dictionary_v2.3.xml.gz").unwrap();
  let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
  let file = BufReader::new(gz_decoder);
  let c: CPEList = quick_xml::de::from_reader(file).unwrap();
  // let mut flag = false;
  for cpe_item in c.cpe_item.into_iter() {
    let _vendor = cpe_item.cpe23_item.name.vendor.to_string();
    let _product = cpe_item.cpe23_item.name.product.to_string();
    // 已经弃用的不再加入数据库
    if cpe_item.name.contains("pdgsoft") {
      println!("{}", cpe_item.cpe23_item.name);
    }
    if cpe_item.deprecated {
      continue;
    }
    continue;
  }
}
