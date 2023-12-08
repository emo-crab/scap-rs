use nvd_cpe::dictionary::CPEList;
use std::fs::File;
use std::io::BufReader;

// https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
fn main() {
  let gz_open_file = File::open("examples/nvdcve/official-cpe-dictionary_v2.3.xml.gz").unwrap();
  let gz_decoder = flate2::read::GzDecoder::new(gz_open_file);
  let file = BufReader::new(gz_decoder);
  let c: CPEList = quick_xml::de::from_reader(file).unwrap();
  if let Some(cpe_item) = c.cpe_item.into_iter().next() {
    println!("{:#?}", &cpe_item);
  }
}
