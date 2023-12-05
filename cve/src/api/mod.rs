use crate::impact::ImpactMetrics;
use crate::v4::configurations::Node;
use crate::v4::{Description, Reference, Weaknesses};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CVE {
  pub id: String,
  pub source_identifier: String,
  pub published: NaiveDateTime,
  // 最后修改时间
  pub last_modified: NaiveDateTime,
  pub vuln_status: VulnStatus,
  pub descriptions: Vec<Description>,
  pub metrics: ImpactMetrics,
  #[serde(default)]
  pub weaknesses: Vec<Weaknesses>,
  #[serde(default)]
  pub configurations: Vec<Node>,
  pub references: Vec<Reference>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum VulnStatus {
  Modified,
  Analyzed,
  #[serde(rename = "Undergoing Analysis")]
  UndergoingAnalysis,
  Rejected,
}

#[cfg(test)]
mod tests {
  use crate::api::CVE;
  use crate::v4::configurations::Node;

  #[test]
  fn nodes() {
    let j = r#"
          [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "1.2.103",
                    "matchCriteriaId": "DCE1E311-F9E5-4752-9F51-D5DA78B7BBFA"
                  }
                ]
              }
            ]"#;
    let i: Vec<Node> = serde_json::from_str(j).unwrap();
    println!("{:?}", i);
  }

  #[test]
  fn cve() {
    let j = r#"{
        "id": "CVE-2023-0001",
        "sourceIdentifier": "psirt@paloaltonetworks.com",
        "published": "2023-02-08T18:15:11.523",
        "lastModified": "2023-11-21T19:15:08.073",
        "vulnStatus": "Undergoing Analysis",
        "descriptions": [
          {
            "lang": "en",
            "value": "An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
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
            },
            {
              "source": "psirt@paloaltonetworks.com",
              "type": "Secondary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H",
                "attackVector": "LOCAL",
                "attackComplexity": "LOW",
                "privilegesRequired": "HIGH",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "NONE",
                "availabilityImpact": "HIGH",
                "baseScore": 6,
                "baseSeverity": "MEDIUM"
              },
              "exploitabilityScore": 0.8,
              "impactScore": 5.2
            }
          ]
        },
        "weaknesses": [
          {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "description": [
              {
                "lang": "en",
                "value": "CWE-319"
              }
            ]
          },
          {
            "source": "psirt@paloaltonetworks.com",
            "type": "Secondary",
            "description": [
              {
                "lang": "en",
                "value": "CWE-319"
              }
            ]
          }
        ],
        "configurations": [
          {
            "operator": "AND",
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:critical_environment:*:*:*",
                    "versionStartIncluding": "7.5",
                    "versionEndExcluding": "7.5.101",
                    "matchCriteriaId": "EC5B0E84-B9A5-4FE3-B2E5-A64AEF57BCF3"
                  }
                ]
              },
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": false,
                    "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                    "matchCriteriaId": "A2572D17-1DE6-457B-99CC-64AFD54487EA"
                  }
                ]
              }
            ]
          }
        ],
        "references": [
          {
            "url": "https://security.paloaltonetworks.com/CVE-2023-0001",
            "source": "psirt@paloaltonetworks.com",
            "tags": [
              "Vendor Advisory"
            ]
          }
        ]
      }"#;
    let i: CVE = serde_json::from_str(j).unwrap();
    println!("{:?}", i);
  }
}
