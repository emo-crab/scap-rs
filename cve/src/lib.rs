#![doc(html_root_url = "https://emo-car.github.io/nvd-rs/cve")]
pub mod cve;
pub mod error;
pub mod node;

use serde::{Deserialize, Serialize};
// https://nvd.nist.gov/general/News/JSON-1-1-Vulnerability-Feed-Release
// https://github.com/CVEProject/cve-schema
#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct CVEContainer {
  // CVE
  pub CVE_data_type: String,
  // 格式 MITRE
  pub CVE_data_format: String,
  // 版本
  pub CVE_data_version: String,
  // CVE 数量
  pub CVE_data_numberOfCVEs: String,
  // 时间
  pub CVE_data_timestamp: String,
  // CVE列表
  pub CVE_Items: Vec<cve::CVEItem>,
}
