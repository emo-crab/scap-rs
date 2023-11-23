use crate::v2::vulnerabilities::Vulnerabilities;
use crate::{Error, NVDApi};
use crate::pagination::Object;

const ROUTER: &str = "cve";

impl NVDApi {
  pub async fn vulnerabilities(&self, query: Vulnerabilities) -> Result<Object, Error> {
    let u = format!("{}/{}", self.base_path, ROUTER);
    self.request(self.client.get(u).query(&query)).await
  }
}
