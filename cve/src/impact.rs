//! impact
use cvss::v2::ImpactMetricV2;
use cvss::v3::ImpactMetricV3;
use serde::{Deserialize, Serialize};

/// This is impact type information (e.g. a text description, CVSSv2, CVSSv3, etc.).
///
/// Must contain: At least one entry, can be text, CVSSv2, CVSSv3, others may be added
///
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all(deserialize = "camelCase"), deny_unknown_fields)]
pub struct ImpactMetrics {
    // TODO: Implement V1?
    // cvssV2 过期
    #[serde(skip_serializing_if = "Option::is_none", alias = "cvssMetricV2")]
    pub base_metric_v2: Option<OneOrMany<ImpactMetricV2>>,
    // cvssV3
    #[serde(skip_serializing_if = "Option::is_none", alias = "cvssMetricV31")]
    pub base_metric_v3: Option<OneOrMany<ImpactMetricV3>>,
    // TODO: Implement V4?
}

// 为了兼容API接口返回的数据和json归档数据结构
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> From<OneOrMany<T>> for Vec<T> {
    fn from(from: OneOrMany<T>) -> Self {
        match from {
            OneOrMany::One(val) => vec![val],
            OneOrMany::Many(vec) => vec,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::impact::ImpactMetrics;

    #[test]
    fn cvss_v3() {
        let j = r#"{
    "baseMetricV3": {
      "cvssV3": {
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "attackVector": "LOCAL",
        "attackComplexity": "LOW",
        "privilegesRequired": "HIGH",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "HIGH",
        "baseScore": 6.7,
        "baseSeverity": "MEDIUM"
      },
      "exploitabilityScore": 0.8,
      "impactScore": 5.9
    }}"#;
        let i: ImpactMetrics = serde_json::from_str(j).unwrap();
        println!("{:?}", i);
    }

    #[test]
    fn test_cvss_v3() {
        let j2 = r#"{"cvssMetricV31":[{
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "NONE",
                "integrityImpact": "NONE",
                "availabilityImpact": "HIGH",
                "baseScore": 7.5,
                "baseSeverity": "HIGH"
              },
              "exploitabilityScore": 3.9,
              "impactScore": 3.6
            }]}"#;
        let i2: ImpactMetrics = serde_json::from_str(j2).unwrap();
        println!("{:?}", i2);
    }
}
