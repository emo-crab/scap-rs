//! [![github]](https://github.com/emo-crab/scap-rs)&ensp;[![crates-io]](https://crates.io/crates/nvd-cvss)&ensp;[![docs-rs]](crate)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! ### Vulnerability Metrics
//! The Common Vulnerability Scoring System (CVSS) is a method used to supply a qualitative measure of severity. CVSS is not a measure of risk. CVSS consists of three metric groups: Base, Temporal, and Environmental. The Base metrics produce a score ranging from 0 to 10, which can then be modified by scoring the Temporal and Environmental metrics. A CVSS score is also represented as a vector string, a compressed textual representation of the values used to derive the score. Thus, CVSS is well suited as a standard measurement system for industries, organizations, and governments that need accurate and consistent vulnerability severity scores. Two common uses of CVSS are calculating the severity of vulnerabilities discovered on one's systems and as a factor in prioritization of vulnerability remediation activities. The National Vulnerability Database (NVD) provides CVSS scores for almost all known vulnerabilities.
//!
//! The NVD supports both Common Vulnerability Scoring System (CVSS) v2.0 and v3.X standards. The NVD provides CVSS 'base scores' which represent the innate characteristics of each vulnerability. The NVD does not currently provide 'temporal scores' (metrics that change over time due to events external to the vulnerability) or 'environmental scores' (scores customized to reflect the impact of the vulnerability on your organization). However, the NVD does supply a CVSS calculator for both CVSS v2 and v3 to allow you to add temporal and environmental score data.
//!
//! CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. The official CVSS documentation can be found at  <https://www.first.org/cvss/>.

#![doc(html_root_url = "https://emo-crab.github.io/scap-rs/cvss")]
// 通用漏洞评分系统
// https://csrc.nist.gov/schema/nvd/feed/1.1-Beta/cvss-v3.x_beta.json
// https://www.first.org/cvss/specification-document
pub mod error;
pub mod metric;
pub mod severity;
pub mod v2;
pub mod v3;
pub mod v4;
pub mod version;
