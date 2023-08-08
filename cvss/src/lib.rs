#![doc(html_root_url = "https://emo-car.github.io/nvd-rs/cvss")]
// 通用漏洞评分系统
// https://csrc.nist.gov/schema/nvd/feed/1.1-Beta/cvss-v3.x_beta.json
// https://www.first.org/cvss/specification-document
pub mod error;
mod metric;
pub mod v2;
pub mod v3;
pub mod version;
