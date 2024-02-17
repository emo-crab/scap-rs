//! [![github]](https://github.com/emo-crab/scap-rs)&ensp;[![crates-io]](https://crates.io/crates/nvd-cves)&ensp;[![docs-rs]](crate)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//!  All vulnerabilities in the NVD have been assigned a CVE identifier and thus, abide by the definition below.
//!
//! CVE defines a vulnerability as:
//!
//! "A weakness in the computational logic (e.g., code) found in software and hardware components that, when exploited, results in a negative impact to confidentiality, integrity, or availability. Mitigation of the vulnerabilities in this context typically involves coding changes, but could also include specification changes or even specification deprecations (e.g., removal of affected protocols or functionality in their entirety)."
//!
//! The Common Vulnerabilities and Exposures (CVE) Program’s primary purpose is to uniquely identify vulnerabilities and to associate specific versions of code bases (e.g., software and shared libraries) to those vulnerabilities. The use of CVEs ensures that two or more parties can confidently refer to a CVE identifier (ID) when discussing or sharing information about a unique vulnerability. For detailed information regarding CVE please refer to <https://cve.org/> or the CNA Rules at <https://www.cve.org/ResourcesSupport/AllResources/CNARules>.
//!
//! <https://nvd.nist.gov/vuln/vulnerability-detail-pages>

#![doc(html_root_url = "https://emo-crab.github.io/scap-rs/cve")]

pub mod api;
pub mod error;
pub mod impact;
pub mod v4;

mod date_format {
  use chrono::NaiveDateTime;
  use serde::{self, Deserialize, Deserializer, Serializer};

  const FORMAT: &str = "%Y-%m-%dT%H:%MZ";

  pub fn serialize<S>(date: &NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let s = date.to_string();
    serializer.serialize_str(&s)
  }

  pub fn deserialize<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    NaiveDateTime::parse_from_str(&s, FORMAT).map_err(serde::de::Error::custom)
  }
}
