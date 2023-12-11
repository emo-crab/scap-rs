//! impact
use nvd_cvss::v2::ImpactMetricV2;
use nvd_cvss::v3::ImpactMetricV3;
use serde::{Deserialize, Serialize};

/// This is impact type information (e.g. a text description, CVSSv2, CVSSv3, etc.).
///
/// Must contain: At least one entry, can be text, CVSSv2, CVSSv3, others may be added
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImpactMetrics {
  // TODO: Implement V1?
  // cvssV2 过期
  #[serde(alias = "cvssMetricV2", default)]
  pub base_metric_v2: OneOrMany<ImpactMetricV2>,
  // cvssV3 会出现同时有V3.0和V3.1的，看是否要分为枚举版本 数组
  #[serde(alias = "cvssMetricV30", default)]
  pub base_metric_v3: OneOrMany<ImpactMetricV3>,
  #[serde(alias = "cvssMetricV31", default)]
  pub base_metric_v31: OneOrMany<ImpactMetricV3>,
  // TODO: Implement V4?
}

impl ImpactMetrics {
  pub fn severity(&self) -> String {
    if let Some(m) = self.base_metric_v3.inner() {
      return m.cvss_v3.base_severity.to_string();
    }
    if let Some(m) = self.base_metric_v2.inner() {
      return m.severity.to_string();
    }
    String::from("None")
  }
}

// 为了兼容API接口返回的数据和json归档数据结构
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
  One(T),
  Many(Vec<T>),
  None,
}

impl<T> Default for OneOrMany<T> {
  fn default() -> Self {
    Self::None
  }
}

impl<T> OneOrMany<T> {
  pub fn inner(&self) -> Option<&T> {
    match self {
      OneOrMany::One(o) => Some(o),
      OneOrMany::Many(l) => l.iter().next(),
      OneOrMany::None => None,
    }
  }
}

impl<T> From<OneOrMany<T>> for Vec<T> {
  fn from(from: OneOrMany<T>) -> Self {
    match from {
      OneOrMany::One(val) => vec![val],
      OneOrMany::Many(vec) => vec,
      OneOrMany::None => vec![],
    }
  }
}
