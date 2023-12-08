//! 7.4. Metric Values
//!
//! Each metric value has an associated constant which is used in the formulas, as defined in Table 16.
//!
//! **Table 16: Metric values**
//!
//!
//! | Metric | Metric Value | Numerical Value |
//! | --- | --- | --- |
//! | Attack Vector / Modified Attack Vector | Network | 0.85 |
//! |  | Adjacent | 0.62 |
//! |  | Local | 0.55 |
//! |  | Physical | 0.2 |
//! | Attack Complexity / Modified Attack Complexity | Low | 0.77 |
//! |  | High | 0.44 |
//! | Privileges Required / Modified Privileges Required | None | 0.85 |
//! |  | Low | 0.62 (or 0.68 if Scope / Modified Scope is Changed) |
//! |  | High | 0.27 (or 0.5 if Scope / Modified Scope is Changed) |
//! | User Interaction / Modified User Interaction | None | 0.85 |
//! |  | Required | 0.62 |
//! | Confidentiality / Integrity / Availability / Modified Confidentiality / Modified Integrity / Modified Availability | High | 0.56 |
//! |  | Low | 0.22 |
//! |  | None | 0 |
//! | Exploit Code Maturity | Not Defined | 1 |
//! |  | High | 1 |
//! |  | Functional | 0.97 |
//! |  | Proof of Concept | 0.94 |
//! |  | Unproven | 0.91 |
//! | Remediation Level | Not Defined | 1 |
//! |  | Unavailable | 1 |
//! |  | Workaround | 0.97 |
//! |  | Temporary Fix | 0.96 |
//! |  | Official Fix | 0.95 |
//! | Report Confidence | Not Defined | 1 |
//! |  | Confirmed | 1 |
//! |  | Reasonable | 0.96 |
//! |  | Unknown | 0.92 |
//! | Confidentiality Requirement / Integrity Requirement / Availability Requirement | Not Defined | 1 |
//! |  | High | 1.5 |
//! |  | Medium | 1 |
//! |  | Low | 0.5 |[](#body)
//!
mod v2;
mod v3;
mod v4;

pub use crate::metric::v2::MetricTypeV2;
pub use crate::metric::v3::MetricTypeV3;
pub use crate::metric::v4::MetricTypeV4;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use std::str::FromStr;

// TODO: 改宏定义
#[derive(Debug, Clone)]
pub struct Help {
  pub worth: Worth,
  pub des: String,
}

#[derive(Debug, Clone)]
pub enum Worth {
  /// 最严重的
  Worst,
  /// 比较严重的
  Worse,
  /// 坏
  Bad,
  /// 还好
  Good,
}

pub trait Metric: Clone + Debug + FromStr + Display {
  const TYPE: MetricType;
  fn name() -> &'static str {
    match Self::TYPE {
      MetricType::V2(v2) => v2.name(),
      MetricType::V3(v3) => v3.name(),
      MetricType::V4(v4) => v4.name(),
    }
  }
  fn help(&self) -> Help;
  fn score(&self) -> f32;
  fn as_str(&self) -> &'static str;
}

pub enum MetricType {
  V2(MetricTypeV2),
  V3(MetricTypeV3),
  V4(MetricTypeV4),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum MetricLevelType {
  Primary,
  Secondary,
}

impl Default for MetricLevelType {
  fn default() -> Self {
    Self::Primary
  }
}
