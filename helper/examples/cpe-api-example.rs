use nvd_api::v2::products::{CpeMatchParameters, CpeParameters};
use nvd_api::ApiVersion;
// https://cwe.mitre.org/data/downloads.html
// curl -s -k https://cwe.mitre.org/data/downloads.html |grep  -Eo '(/[^"]*\.xml.zip)'|xargs -I % wget -c https://cwe.mitre.org%
#[tokio::main]
async fn main() {
  let api = nvd_api::NVDApi::new(None, ApiVersion::default()).unwrap();
  let cpe = api
    .cpe(CpeParameters {
      cpe_name_id: None,
      cpe_match_string: None,
      keyword: None,
      last_mod: None,
      match_criteria_id: None,
      limit_offset: None,
    })
    .await
    .unwrap();
  println!("{:?}", cpe.format);
  let cpe_match = api
    .cpe_match(CpeMatchParameters {
      cve_id: None,
      last_mod: None,
      match_criteria_id: None,
      keyword: None,
      limit_offset: None,
    })
    .await
    .unwrap();
  println!("{:?}", cpe_match.format);
}
