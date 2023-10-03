//! impact
use serde::{Deserialize, Serialize};
use cvss::v2::ImpactMetricV2;
use cvss::v3::ImpactMetricV3;

/// This is impact type information (e.g. a text description, CVSSv2, CVSSv3, etc.).
///
/// Must contain: At least one entry, can be text, CVSSv2, CVSSv3, others may be added
///
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase"), deny_unknown_fields)]
pub struct Impact {
  // TODO: Implement V1?
  // cvssV2 过期
  #[serde(skip_serializing_if = "Option::is_none")]
  pub base_metric_v2: Option<ImpactMetricV2>,
  // cvssV3
  pub base_metric_v3: Option<ImpactMetricV3>,
  // TODO: Implement V4?
}

