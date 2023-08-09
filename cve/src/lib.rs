#![doc(html_root_url = "https://emo-car.github.io/nvd-rs/cve")]
//!
pub mod cve;
pub mod error;
pub mod node;

use serde::{Deserialize, Serialize};
// https://nvd.nist.gov/general/News/JSON-1-1-Vulnerability-Feed-Release
// https://github.com/CVEProject/cve-schema
// https://cveproject.github.io/cve-schema/schema/v5.0/docs/mindmap.html
// https://raw.gitmirror.com/CVEProject/cve-schema/master/schema/v4.0/DRAFT-JSON-file-format-v4.md
// https://www.cve.org/Downloads
// https://github.com/CVEProject/cvelist

/// These objects can in turn contain more objects, arrays, strings and so on. The reason for this is so that each top level object type can contain self-identifying data such as CVE_Data_version. Most objects can in turn contains virtually any other object. In general, if you traverse into the nested tree of objects you should not encounter any chains that contains more than one instance of a given object container. Simply put you should not for example encounter a chain such as: root, CVE_affects, CVE_configuration, CVE_workaround, CVE_configuration. Please note that this rule may be subject to change as we get new container types and use cases.
#[derive(Debug, Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct CVEContainer {
  /// This string identifies what kind of data is held in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what kind of file this is. Valid values for this string are CVE, CNA, CVEMENTOR.
  pub CVE_data_type: String,
  /// This string identifies what data format is used in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what format of data is used. Valid values for this string are MITRE, it can also be user defined (e.g. for internal use).
  pub CVE_data_format: String,
  /// This identifies which version of the data format is in use. This is mandatory and designed to prevent problems with attempting to detect what format of data is used.
  pub CVE_data_version: String,
  // CVE 数量
  pub CVE_data_numberOfCVEs: String,
  /// Timestamps
  pub CVE_data_timestamp: String,
  // CVE列表
  pub CVE_Items: Vec<cve::CVEItem>,
}
