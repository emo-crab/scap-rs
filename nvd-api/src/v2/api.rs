use crate::pagination::Object;
use crate::v2::vulnerabilities::CveParameters;
use crate::{Error, NVDApi};

const ROUTER: &str = "cve";

impl NVDApi {
  pub async fn vulnerabilities(&self, query: CveParameters) -> Result<Object, Error> {
    let u = format!("{}/{}/{}", self.base_path, self.version, ROUTER);
    self.request(self.client.get(u).query(&query)).await
  }
}
