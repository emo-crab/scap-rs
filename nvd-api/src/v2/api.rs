use crate::pagination::Object;
use crate::v2::products::{CpeMatchParameters, CpeParameters};
use crate::v2::vulnerabilities::CveParameters;
use crate::{Error, NVDApi};

impl NVDApi {
  pub async fn cve(&self, query: CveParameters) -> Result<Object, Error> {
    let u = format!("{}/{}/{}", self.base_path, "cves", self.version);
    self.request(self.client.get(u).query(&query)).await
  }
  pub async fn cve_history(&self, query: CveParameters) -> Result<Object, Error> {
    let u = format!("{}/{}/{}", self.base_path, "cvehistory", self.version);
    self.request(self.client.get(u).query(&query)).await
  }
  pub async fn cpe(&self, query: CpeParameters) -> Result<Object, Error> {
    let u = format!("{}/{}/{}", self.base_path, "cpes", self.version);
    self.request(self.client.get(u).query(&query)).await
  }
  pub async fn cpe_match(&self, query: CpeMatchParameters) -> Result<Object, Error> {
    let u = format!("{}/{}/{}", self.base_path, "cpematch", self.version);
    self.request(self.client.get(u).query(&query)).await
  }
}
